'use strict';

/**
 * hwid_patch.js —— 机器标识改写器
 * =================================
 *
 * 干什么
 * ------
 * 在游戏进程里拦截 kernel32!GetSystemFirmwareTable()，当调用者读到的是
 * 原始 SMBIOS 表（签名 "RSMB"）时，把表里的系统序列号 / 主板序列号 /
 * 机箱序列号 / 系统 UUID 换成我们准备好的假身份，再把缓冲区原样交回去。
 *
 * 为什么这样做
 * ------------
 * 目标反作弊的机器码完全由 SMBIOS 表推导，且只在启动阶段读一次。
 * 它读的不是 WMI 包装后的数据，而是这张原始表，所以直接改缓冲区即可，
 * 不需要驱动、不需要改注册表、不动磁盘上的任何文件。
 *
 * 为什么必须"等长"改写
 * --------------------
 * SMBIOS 不是定长结构体数组，而是一条变长记录流。每条记录后面挂着一组
 * ASCII 字符串，字符串之间用单个 \0 分隔，整组以连续两个 \0 结束。
 * 字符串长度一变，后面所有记录的起始偏移都会错位，整张表就无法解析。
 * 因此这里只做等长覆盖：短了用空格补，长了截断。
 *
 * 为什么只改"目标模块发起的调用"
 * ------------------------------
 * 同一个进程里，Steam / Unity / 显卡驱动都会读 SMBIOS 判断硬件型号。
 * 全都改会干扰它们（可能导致渲染或硬件识别异常），日志也会被淹没。
 * 所以只在调用者属于目标模块时才动手，其它调用原样放行。
 *
 * 兼容性
 * ------
 * Frida 17.x，Windows x64。
 */

const CONFIG = {
  /**
   * 只处理由这个模块发起的调用。设为 null 则处理所有调用者（不推荐）。
   * 匹配的是调用指令所在模块的文件名。
   */
  onlyFromModule: /SL-AC\.dll/i,

  /** 日志条数上限，避免长时间运行把日志刷爆。 */
  logBudget: 80,

  /**
   * 日志脱敏。
   *
   * 日志里同时出现「原始机器码」和「伪造机器码」，一旦被截图或上传，
   * 等于把自己的真实机器指纹公开。默认只保留首尾几位，中间用 * 覆盖，
   * 这样依然能一眼比对"改前 / 改后是不是不一样"，但看不出完整值。
   *
   * 需要完整值排错时，把 enabled 改成 false（不建议长期保持）。
   */
  mask: {
    enabled: true,
    keepStart: 3, // 保留开头几位
    keepEnd: 2, // 保留结尾几位
  },

  /**
   * 新的机器身份。长度不必与真值一致：
   *   - 比真值短 → 用空格补齐
   *   - 比真值长 → 截断
   * 只要最终写回的长度与原字符串一致，表结构就是合法的。
   */
  identity: {
    // 下面是占位示例值，第一次使用前请换成你自己的。
    // 长度随意：写入时会按目标字符串的实际长度截断或空格补齐。
    systemSerial: 'EXAMPLE000000001',
    boardSerial: 'EXAMPLE0001',
    chassisSerial: 'EXAMPLE000000001',
    systemUuid: [
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ],
  },
};

const START = Date.now();

/* ------------------------------------------------------------------ */
/* 日志                                                                */
/* ------------------------------------------------------------------ */

let logRemaining = CONFIG.logBudget;

/**
 * 把一行日志同时送到 stdout 和宿主进程（Python 侧），两边都能看到。
 * 超出预算后静默丢弃，避免高频 hook 拖慢游戏。
 */
function emit(tag, message) {
  if (logRemaining-- <= 0) return;
  try {
    send({ tag: tag, msg: message, t: Date.now() - START });
  } catch (e) {
    /* 宿主已断开，忽略 */
  }
}

/**
 * 字符串脱敏：保留首尾各几位，中间替换成 *。
 *
 *   ABCDEFGHIJKLMNO  ->  ABC***********NO
 *
 * 太短的串（首尾保留位数之和已经覆盖全部）整体打码，
 * 避免出现"打了码但等于没打"的情况。
 */
function maskSecret(text) {
  if (!CONFIG.mask.enabled) return text;
  if (!text) return text;

  const keep = CONFIG.mask.keepStart + CONFIG.mask.keepEnd;
  if (text.length <= keep) return '*'.repeat(text.length);

  return (
    text.slice(0, CONFIG.mask.keepStart) +
    '*'.repeat(text.length - keep) +
    text.slice(text.length - CONFIG.mask.keepEnd)
  );
}

/** 十六进制串（UUID）脱敏：只留首尾 4 个字符。 */
function maskHex(hex) {
  if (!CONFIG.mask.enabled) return hex;
  if (!hex || hex.length <= 8) return '*'.repeat((hex || '').length);
  return hex.slice(0, 4) + '…' + hex.slice(-4);
}

/* ------------------------------------------------------------------ */
/* 模块与导出解析                                                      */
/* ------------------------------------------------------------------ */

/**
 * Frida 17 移除了部分静态 API，这里按三代写法依次尝试，
 * 保证在新旧版本上都能拿到导出地址。
 */
function resolveExport(moduleName, exportName) {
  try {
    const addr = Module.getExportByName(moduleName, exportName);
    if (addr) return addr;
  } catch (e) {}

  try {
    const mod = Process.getModuleByName(moduleName);
    const addr = mod.getExportByName(exportName);
    if (addr) return addr;
  } catch (e) {}

  return null;
}

/**
 * 把返回地址翻译成「模块名+偏移」，用来判断这次调用是谁发起的。
 * 只在 onLeave 里可靠：Windows 上 onEnter 的 ctx.returnAddress 是空的。
 */
function describeCaller(ctx) {
  try {
    const ret = ctx.returnAddress;
    if (!ret) return null;
    const mod = Process.findModuleByAddress(ret);
    if (!mod) return { module: null, text: ret.toString() };
    return {
      module: mod.name,
      text: mod.name + '+0x' + ret.sub(mod.base).toString(16),
    };
  } catch (e) {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* SMBIOS 解析                                                         */
/* ------------------------------------------------------------------ */

/**
 * 从字符串集起点开始读，返回字符串列表以及下一条结构的起始偏移。
 *
 * 字符串集布局：
 *   "str1\0str2\0\0"
 * 读法：读到 \0 结束一个字符串；如果紧接着又是 \0，说明整组结束。
 * 没有任何字符串时，格式化区后面直接就是两个 \0。
 */
function readStringSet(bytes, start) {
  const strings = [];
  let cursor = start;

  if (cursor >= bytes.length) return { strings: strings, next: cursor };
  if (bytes[cursor] === 0) return { strings: strings, next: cursor + 2 };

  while (cursor < bytes.length && bytes[cursor] !== 0) {
    const offset = cursor;
    while (cursor < bytes.length && bytes[cursor] !== 0) cursor++;
    strings.push({ offset: offset, length: cursor - offset });
    cursor++; // 跳过这个字符串的结束符
    if (cursor >= bytes.length) break;
    if (bytes[cursor] === 0) return { strings: strings, next: cursor + 1 };
  }

  return { strings: strings, next: cursor };
}

/**
 * 遍历整张表，返回每条结构的信息：
 *   { type, offset, formattedLength, strings: [{offset, length}] }
 *
 * 表头 8 字节：'RSMB' + 表长度(1) + 校验和(1) + SMBIOS 版本(2)，之后才是结构。
 * type=127 是 End-of-Table，遇到就停。
 */
function walkStructures(bytes) {
  const list = [];
  let offset = 8;

  while (offset + 4 <= bytes.length) {
    const type = bytes[offset];
    const formattedLength = bytes[offset + 1];
    if (formattedLength < 4) break; // 长度字段非法，表已损坏

    const set = readStringSet(bytes, offset + formattedLength);
    list.push({
      type: type,
      offset: offset,
      formattedLength: formattedLength,
      strings: set.strings,
    });

    if (type === 127) break;
    offset = set.next;
  }

  return list;
}

/** 读结构格式化区里某个偏移处的字段值（通常是字符串索引，0 表示「无」）。 */
function fieldIndex(bytes, struct, fieldOffset) {
  const at = struct.offset + fieldOffset;
  return at < bytes.length ? bytes[at] : 0;
}

/* ------------------------------------------------------------------ */
/* 改写计划                                                            */
/* ------------------------------------------------------------------ */

/** 取结构里某个字段指向的字符串描述（在缓冲区中的偏移与长度）。 */
function fieldString(bytes, struct, fieldOffset) {
  if (!struct) return null;
  const index = fieldIndex(bytes, struct, fieldOffset);
  if (!index) return null;
  return struct.strings[index - 1] || null;
}

/**
 * 在结构的格式化区里，找第一个「指向指定内容字符串」的字段偏移。
 *
 * 为什么需要这个函数：不同厂商的 Type 3（机箱）字段顺序并不统一。
 * 实测某台机器把 Version 放在 0x06、Serial 放在 0x05，按规范偏移 0x06
 * 去改会改到 "1.0"（版本号），机箱序列号反而没变。
 * 用「内容与系统序列号相同」来定位字段，可以绕开厂商差异。
 *
 * 返回字段偏移；找不到返回 -1，调用方负责退回规范偏移。
 */
function findFieldByStringValue(bytes, struct, value) {
  if (!struct || value === null || value === undefined) return -1;
  for (let fieldOffset = 4; fieldOffset < struct.formattedLength; fieldOffset++) {
    const target = fieldString(bytes, struct, fieldOffset);
    if (!target) continue;
    if (decodeAscii(bytes, target.offset, target.length) === value) return fieldOffset;
  }
  return -1;
}

/**
 * 同一段字符串可能被多条结构引用（系统序列号和机箱序列号经常共用），
 * 所以不直接写，而是先按「缓冲区偏移」合并成计划，最后统一落盘。
 * 这样既能避免重复写，也能发现两条结构要求写入不同值的情况。
 */
function planString(bytes, tasks, struct, fieldOffset, newValue, label) {
  if (!struct) return;
  const index = fieldIndex(bytes, struct, fieldOffset);
  if (!index) return;

  const target = struct.strings[index - 1];
  if (!target) return;

  const existing = tasks.get(target.offset);
  if (existing) {
    if (existing.value !== newValue) {
      emit('WARN', label + ': 同一字符串被要求写入不同值，保留先到的');
    }
    return;
  }

  tasks.set(target.offset, {
    length: target.length,
    value: newValue,
    label: label,
  });
}

/** 把字符串按等长规则编码：截断或空格补齐。 */
function encodeFixedLength(text, length) {
  const out = new Uint8Array(length);
  out.fill(0x20); // 先填空格
  for (let i = 0; i < length; i++) {
    out[i] = i < text.length ? text.charCodeAt(i) & 0xff : 0x20;
  }
  return out;
}

/** 读出缓冲区里一段 ASCII，用来在日志里显示"改前长什么样"。 */
function decodeAscii(bytes, offset, length) {
  let s = '';
  for (let i = 0; i < length; i++) s += String.fromCharCode(bytes[offset + i]);
  return s;
}

/** 十六进制显示，用于 UUID 前后对比。 */
function toHex(bytes, offset, length) {
  const parts = [];
  for (let i = 0; i < length; i++) {
    parts.push(bytes[offset + i].toString(16).padStart(2, '0'));
  }
  return parts.join('');
}

/**
 * 对整张表执行改写。返回给日志用的说明文字数组。
 * 传入的 bytes 会被原地修改。
 */
function applyIdentity(bytes) {
  const structures = walkStructures(bytes);
  const report = [];

  // ---- 1) 串号类字段：按字段索引定位字符串，等长覆盖 ----
  const byType = {};
  for (const s of structures) {
    if (!(s.type in byType)) byType[s.type] = s;
  }

  const tasks = new Map(); // 缓冲区偏移 -> {length, value, label}

  // Type 1（System Information）：格式化区 0x04 Manufacturer / 0x05 Product /
  // 0x06 Version / 0x07 Serial Number
  const SYSTEM_SERIAL_FIELD = 7;

  // 先记下系统序列号的原始内容，后面用它去其它结构里找「值相同」的字段
  const originalSystemSerial = (function () {
    const target = fieldString(bytes, byType[1], SYSTEM_SERIAL_FIELD);
    return target ? decodeAscii(bytes, target.offset, target.length) : null;
  })();

  planString(
    bytes, tasks, byType[1], SYSTEM_SERIAL_FIELD,
    CONFIG.identity.systemSerial, 'T1 System Serial'
  );

  // Type 2（Baseboard）：0x07 Serial Number
  planString(bytes, tasks, byType[2], 7, CONFIG.identity.boardSerial, 'T2 Board Serial');

  // Type 3（Chassis）：规范是 0x06 Serial Number，但厂商实现不统一，
  // 因此优先按「内容等于系统序列号」找字段，找不到再退回 0x06。
  let chassisField = findFieldByStringValue(bytes, byType[3], originalSystemSerial);
  if (chassisField < 0) chassisField = 6;
  planString(bytes, tasks, byType[3], chassisField, CONFIG.identity.chassisSerial, 'T3 Chassis Serial');

  for (const [offset, task] of tasks) {
    const before = decodeAscii(bytes, offset, task.length);
    bytes.set(encodeFixedLength(task.value, task.length), offset);
    const after = decodeAscii(bytes, offset, task.length);
    report.push(task.label + ': "' + maskSecret(before) + '" -> "' + maskSecret(after) + '"');
  }

  // ---- 2) 系统 UUID：Type 1 格式化区偏移 0x08，16 字节二进制 ----
  const system = byType[1];
  if (system && system.formattedLength >= 24) {
    const uuidOffset = system.offset + 8;
    const before = toHex(bytes, uuidOffset, 16);
    const uuid = CONFIG.identity.systemUuid;
    for (let i = 0; i < 16; i++) bytes[uuidOffset + i] = uuid[i] & 0xff;
    report.push('T1 System UUID: ' + maskHex(before) + ' -> ' + maskHex(toHex(bytes, uuidOffset, 16)));
  }

  return report;
}

/* ------------------------------------------------------------------ */
/* 安装 hook                                                           */
/* ------------------------------------------------------------------ */

const target = resolveExport('kernel32.dll', 'GetSystemFirmwareTable');

if (!target) {
  emit('ERROR', '解析不到 kernel32!GetSystemFirmwareTable，本机可能不是常规 Windows');
} else {
  Interceptor.attach(target, {
    /**
     * onEnter：只记录参数，不动任何数据。
     *
     * 函数原型（Windows 头文件）：
     *   UINT GetSystemFirmwareTable(DWORD ProviderSignature,
     *                               DWORD TableID,
     *                               PVOID Buffer,
     *                               DWORD BufferSize);
     * 对应 args[0..3]。
     */
    onEnter: function (a) {
      const signature = a[0].toUInt32();

      // signature 是 4 字节整数。'RSMB' 在内存中为 52 53 4D 42，
      // 按小端解释成整数是 0x424D5352，所以要从高位字节往低位拼。
      this.provider = String.fromCharCode(
        (signature >> 24) & 0xff,
        (signature >> 16) & 0xff,
        (signature >> 8) & 0xff,
        signature & 0xff
      );

      this.buffer = a[2];
      this.bufferSize = a[3].toUInt32();
    },

    /**
     * onLeave：函数已经返回，缓冲区被填好了，这时才改写。
     *
     * 调用约定上，Windows 的惯例是先调一次问长度（BufferSize=0、Buffer=NULL），
     * 拿到返回值后再调一次真正取数据。第一次必须跳过。
     */
    onLeave: function (retval) {
      const written = retval.toInt32();

      // 跳过"问长度"那次：没有缓冲区，或者缓冲区小于实际写入量。
      if (written <= 8 || !this.buffer || this.buffer.isNull()) return;
      if (this.bufferSize < written) return;

      // 只处理原始 SMBIOS 表；ACPI 等其它固件表（'FIRM'、'FACP' …）放行。
      if (this.provider !== 'RSMB') return;

      // 只处理目标模块发起的调用，见文件头说明。
      const caller = describeCaller(this);
      if (CONFIG.onlyFromModule) {
        if (!caller || !caller.module || !CONFIG.onlyFromModule.test(caller.module)) return;
      }

      try {
        const bytes = new Uint8Array(this.buffer.readByteArray(written));
        const report = applyIdentity(bytes);

        // Uint8Array 直接传可能不被接受，转成普通数组写回。
        this.buffer.writeByteArray(Array.from(bytes));

        emit(
          'PATCH',
          '表已改写：长度=' + written + ' 字段=' + report.length +
            ' 调用者=' + (caller ? caller.text : '?')
        );
        for (const line of report) emit('FIELD', line);
      } catch (e) {
        emit('ERROR', '改写失败：' + e.message);
      }
    },
  });

  emit(
    'READY',
    '改写器已安装：serial=' + maskSecret(CONFIG.identity.systemSerial) +
      ' board=' + maskSecret(CONFIG.identity.boardSerial)
  );
}
