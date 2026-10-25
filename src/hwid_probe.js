'use strict';

/**
 * hwid_probe.js —— 机器指纹采集面侦察器
 * ======================================
 *
 * 适用版本：SCP: Secret Laboratory 14.2.8（实测采集面与调用者）。
 * 换版本后用它重新摸底，再决定改写器要不要跟着改。
 *
 * 干什么
 * ------
 * 不修改任何数据，只旁观：把目标进程里那些"能拿到机器唯一标识"的系统 API
 * 全部挂上钩子，记录每一次调用的参数、返回值，以及**是谁发起的**。
 *
 * 为什么需要它
 * ------------
 * 想知道反作弊的机器码到底由哪些硬件/系统标识组成，靠静态分析很难得出结论
 * （目标样本被商业壳虚拟化，函数体不可分析）。但运行时它必须调用系统 API，
 * 而这些调用点是可以完整记录的。记录下来的清单，就是机器码的输入集合。
 *
 * 关键设计：调用者归属
 * --------------------
 * 同一个进程里，Steam / Unity / 驱动都会调用这些 API。所以每条日志都带
 * "调用者模块+偏移"，只有调用者属于目标模块的记录才有意义。
 *
 * 注意：Windows 上 Frida 的 onEnter 上下文里 returnAddress 是空的，
 * 必须等到 onLeave 才能反查调用者模块。这是本脚本所有 hook 都采用
 * "onEnter 存参数、onLeave 判归属并出日志" 结构的原因。
 *
 * 用法
 * ----
 * 由 spawn_probe.py 在进程挂起时载入，或在游戏运行时 attach 后载入。
 */

/**
 * 内置默认值。实际配置来自仓库根目录的 config.json 的 js."hwid_probe.js" 段，
 * 由 Python 侧注入成 globalThis.__SLSPOOFER_CONFIG__；这里做合并与兜底。
 */
const DEFAULTS = {
  /** 目标模块：只有它发起的调用才值得关注。字符串会转成正则。 */
  targetModule: 'SL-AC\\.dll',

  /** 日志上限，防止长时间运行刷爆管道。 */
  logBudget: 1200,

  /**
   * 是否把读到的 SMBIOS 表内容打印到日志。
   *
   * 默认关闭：这张表里就是完整机器码（整机序列号、主板序列号、系统 UUID），
   * 日志一旦被截图或上传就等于公开。真正排错时再临时打开。
   */
  dumpTable: false,

  /** 是否对注册表里读到的长文本值（MachineGuid 等）做打码。 */
  maskSecrets: true,
};

/** 深合并，规则与 hwid_patch.js 保持一致。 */
function mergeDefaults(defaults, override) {
  const source = override && typeof override === 'object' ? override : {};
  const result = {};

  for (const key of Object.keys(defaults)) {
    const defaultValue = defaults[key];
    const overrideValue = source[key];

    if (
      defaultValue &&
      typeof defaultValue === 'object' &&
      !Array.isArray(defaultValue)
    ) {
      result[key] = mergeDefaults(defaultValue, overrideValue);
    } else {
      result[key] = overrideValue === undefined ? defaultValue : overrideValue;
    }
  }

  for (const key of Object.keys(source)) {
    if (!(key in result)) result[key] = source[key];
  }

  return result;
}

const CONFIG = mergeDefaults(DEFAULTS, globalThis.__SLSPOOFER_CONFIG__ || {});

// JSON 里写不了正则字面量，配置里用字符串表示，这里转回正则
if (typeof CONFIG.targetModule === 'string') {
  CONFIG.targetModule = new RegExp(CONFIG.targetModule, 'i');
}

const START = Date.now();
let logRemaining = CONFIG.logBudget;

/* ------------------------------------------------------------------ */
/* 基础工具                                                            */
/* ------------------------------------------------------------------ */

function emit(tag, message) {
  if (logRemaining-- <= 0) return;
  try {
    send({ tag: tag, msg: message, t: Date.now() - START });
  } catch (e) {}
}

/**
 * 长文本脱敏：保留首尾各几位，中间打码。
 *
 * 注册表里读到的 MachineGuid、产品序列号之类同样是机器唯一标识，
 * 侦察日志也不应该原样留下。短值（< 8 字符）原样返回，避免把
 * "AMD64" 这种无关紧要的值也打成一串星号。
 */
function maskSecret(text) {
  if (!CONFIG.maskSecrets) return text;
  if (!text || text.length < 8) return text;
  const head = 3;
  const tail = 2;
  return text.slice(0, head) + '*'.repeat(text.length - head - tail) + text.slice(-tail);
}

/** 兼容 Frida 17 的三种导出解析写法。 */
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

/** 读 UTF-16 字符串，失败返回占位符而不是抛异常。 */
function readUtf16(ptr) {
  try {
    return !ptr || ptr.isNull() ? '' : ptr.readUtf16String();
  } catch (e) {
    return '<unreadable>';
  }
}

/** 读一段以 \0 结尾的 ASCII。 */
function readAsciiZ(ptr) {
  try {
    if (!ptr || ptr.isNull()) return '';
    return ptr.readCString();
  } catch (e) {
    return '';
  }
}

/** 把内存里的一段字节渲染成可读文本，用于 dump 缓冲区。 */
function preview(ptr, length, limit) {
  try {
    if (!ptr || ptr.isNull() || length <= 0) return '';
    const bytes = new Uint8Array(ptr.readByteArray(Math.min(length, limit || 256)));
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      const c = bytes[i];
      out += c >= 32 && c < 127 ? String.fromCharCode(c) : '.';
    }
    return out;
  } catch (e) {
    return '<unreadable>';
  }
}

/**
 * 通用 hook 安装器。
 *
 * enter(args) 里只保存参数，不要做判断；
 * leave(retval) 里 this.$caller / this.$isTarget 已就绪，可以出日志。
 *
 * 这样安排的原因见文件头"关键设计：调用者归属"。
 */
function hookExport(moduleName, exportName, enter, leave) {
  const addr = resolveExport(moduleName, exportName);
  if (!addr) {
    emit('SKIP', moduleName + '!' + exportName + ' 未找到导出，跳过');
    return;
  }

  Interceptor.attach(addr, {
    onEnter: function (args) {
      try {
        enter && enter.call(this, args);
      } catch (e) {
        emit('ERROR', exportName + ' onEnter: ' + e.message);
      }
    },
    onLeave: function (retval) {
      try {
        let callerModule = null;
        let callerText = '?';
        const ret = this.returnAddress;
        if (ret) {
          const mod = Process.findModuleByAddress(ret);
          if (mod) {
            callerModule = mod.name;
            callerText = mod.name + '+0x' + ret.sub(mod.base).toString(16);
          } else {
            callerText = ret.toString();
          }
        }
        this.$caller = callerText;
        this.$isTarget = callerModule ? CONFIG.targetModule.test(callerModule) : false;

        leave && leave.call(this, retval);
      } catch (e) {
        emit('ERROR', exportName + ' onLeave: ' + e.message);
      }
    },
  });
}

/* ------------------------------------------------------------------ */
/* 1. 注册表                                                           */
/* ------------------------------------------------------------------ */
/**
 * MachineGuid、BIOS 信息、网卡 NetworkAddress 都可能藏在注册表里。
 * 同时挂 Win32 版和 Native 版：壳/反作弊经常绕过 advapi32 直接调 ntdll。
 */
hookExport(
  'advapi32.dll',
  'RegQueryValueExW',
  function (args) {
    this.valueName = readUtf16(args[1]);
    this.dataPtr = args[4];
    this.dataSizePtr = args[5];
  },
  function (retval) {
    if (!this.$isTarget || retval.toInt32() !== 0 || !this.valueName) return;
    let value = '';
    try {
      if (this.dataPtr && !this.dataPtr.isNull() && this.dataSizePtr && !this.dataSizePtr.isNull()) {
        if (this.dataSizePtr.readU32() > 0) value = this.dataPtr.readUtf16String();
      }
    } catch (e) {
      value = '<binary>';
    }
    emit('REG', this.valueName + ' = ' + maskSecret(value) + '   <- ' + this.$caller);
  }
);

hookExport(
  'advapi32.dll',
  'RegOpenKeyExW',
  function (args) {
    this.keyName = readUtf16(args[1]);
  },
  function (retval) {
    if (!this.$isTarget || retval.toInt32() !== 0) return;
    emit('REGKEY', this.keyName + '   <- ' + this.$caller);
  }
);

hookExport(
  'ntdll.dll',
  'NtQueryValueKey',
  function (args) {
    // KEY_VALUE_FULL_INFORMATION 的输出缓冲区，结构在 onLeave 里解析
    this.info = args[3];
    this.valueName = '';
    try {
      const us = args[1]; // UNICODE_STRING：Length(2) MaximumLength(2) Padding(4) Buffer(8)
      const length = us.readU16();
      const buffer = us.add(8).readPointer();
      this.valueName = length > 0 ? buffer.readUtf16String(length / 2) : '';
    } catch (e) {}
  },
  function (retval) {
    if (!this.$isTarget || retval.toInt32() < 0 || !this.valueName) return;
    let value = '';
    try {
      // KEY_VALUE_FULL_INFORMATION：DataLength(4) 在 0x08，DataOffset(4) 在 0x0C
      const dataLength = this.info.add(8).readU32();
      if (dataLength > 0) value = preview(this.info, dataLength, 200);
    } catch (e) {}
    emit('NTREG', this.valueName + ' = ' + value + '   <- ' + this.$caller);
  }
);

/* ------------------------------------------------------------------ */
/* 2. 卷序列号                                                         */
/* ------------------------------------------------------------------ */
hookExport(
  'kernel32.dll',
  'GetVolumeInformationW',
  function (args) {
    this.root = readUtf16(args[0]);
    this.serialPtr = args[3];
  },
  function (retval) {
    if (!this.$isTarget) return;
    let serial = '?';
    try {
      if (this.serialPtr && !this.serialPtr.isNull()) {
        serial = '0x' + this.serialPtr.readU32().toString(16).padStart(8, '0');
      }
    } catch (e) {}
    emit('VOLUME', '根目录=' + this.root + ' 序列号=' + serial + '   <- ' + this.$caller);
  }
);

/* ------------------------------------------------------------------ */
/* 3. 磁盘 / 存储                                                      */
/* ------------------------------------------------------------------ */
/**
 * 磁盘硬件序列号只能通过 IOCTL 拿到，常见两种通道：
 *   - DeviceIoControl（kernel32 封装）
 *   - NtDeviceIoControlFile（ntdll 原生，壳常用）
 * 两者都挂，才能确认目标走的哪条路。
 */
const STORAGE_IOCTLS = {
  0x002d1400: 'IOCTL_STORAGE_QUERY_PROPERTY', // 返回 STORAGE_DEVICE_DESCRIPTOR（含 Vendor/Product/Serial）
  0x0007c088: 'IOCTL_SMART_RCV_DRIVE_DATA', // 直读 SMART，可取硬盘型号与序列号
  0x00074080: 'IOCTL_DISK_GET_DRIVE_LAYOUT_EX',
  0x000700a0: 'IOCTL_DISK_GET_DRIVE_GEOMETRY',
  0x00070000: 'IOCTL_DISK_GET_DRIVE_GEOMETRY_EX',
  0x0004d004: 'IOCTL_SCSI_MINIPORT',
  0x0004d008: 'IOCTL_SCSI_PASS_THROUGH_DIRECT',
  0x0056c040: 'IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS',
};

/**
 * 解析 STORAGE_DEVICE_DESCRIPTOR 里的厂商/型号/序列号。
 * 结构布局（相对缓冲区起点）：
 *   0x0C VendorIdOffset，0x10 ProductIdOffset，0x14 ProductRevisionOffset，0x18 SerialNumberOffset
 * 每个 Offset 指向缓冲区内的 ASCII 字符串。
 */
function describeStorageDevice(buffer, length) {
  if (!buffer || buffer.isNull() || length < 32) return '';
  try {
    const vendor = readAsciiZ(buffer.add(buffer.add(12).readU32()));
    const product = readAsciiZ(buffer.add(buffer.add(16).readU32()));
    const revision = readAsciiZ(buffer.add(buffer.add(20).readU32()));
    const serial = readAsciiZ(buffer.add(buffer.add(24).readU32()));
    return ' [厂商=' + vendor + ' 型号=' + product + ' 版本=' + revision + ' 序列号=' + serial + ']';
  } catch (e) {
    return '';
  }
}

hookExport(
  'kernel32.dll',
  'DeviceIoControl',
  function (args) {
    this.code = args[1].toUInt32();
    this.outBuffer = args[4];
    this.bytesReturnedPtr = args[6];
  },
  function (retval) {
    if (!this.$isTarget || retval.toInt32() === 0) return;
    const name = STORAGE_IOCTLS[this.code];
    if (!name) return;
    let returned = 0;
    try {
      if (this.bytesReturnedPtr && !this.bytesReturnedPtr.isNull()) {
        returned = this.bytesReturnedPtr.readU32();
      }
    } catch (e) {}
    const detail = this.code === 0x002d1400 ? describeStorageDevice(this.outBuffer, returned) : '';
    emit('IOCTL', name + ' 返回字节=' + returned + detail + '   <- ' + this.$caller);
  }
);

hookExport(
  'ntdll.dll',
  'NtDeviceIoControlFile',
  function (args) {
    this.code = args[1].toUInt32();
    this.outBuffer = args[4];
    this.ioStatusBlock = args[6];
  },
  function (retval) {
    if (!this.$isTarget || retval.toInt32() < 0) return;
    const name = STORAGE_IOCTLS[this.code];
    if (!name) return;
    let returned = 0;
    try {
      // IO_STATUS_BLOCK：Status(4 或 8) 之后是 Information(8)，表示实际写入字节数
      returned = this.ioStatusBlock.add(8).readU64().toNumber();
    } catch (e) {}
    const detail = this.code === 0x002d1400 ? describeStorageDevice(this.outBuffer, returned) : '';
    emit('NTIOCTL', name + ' 返回字节=' + returned + detail + '   <- ' + this.$caller);
  }
);

/* ------------------------------------------------------------------ */
/* 4. SMBIOS / 固件表                                                  */
/* ------------------------------------------------------------------ */
/**
 * 这是重点监控项：原始 SMBIOS 表包含 BIOS 厂商、主板型号、整机序列号、
 * 系统 UUID、机箱序列号，是机器码最常用的来源。
 *
 * 'RSMB' 是原始表；也有程序用 'FIRM'（固件表）、'FACP'（ACPI）。
 */
hookExport(
  'kernel32.dll',
  'GetSystemFirmwareTable',
  function (args) {
    const signature = args[0].toUInt32();
    // 按大端顺序拼出可读签名（'RSMB' 在内存里是 52 53 4D 42）
    this.signature = String.fromCharCode(
      (signature >> 24) & 0xff,
      (signature >> 16) & 0xff,
      (signature >> 8) & 0xff,
      signature & 0xff
    );
    this.tableId = args[1].toUInt32();
    this.buffer = args[2];
    this.bufferSize = args[3].toUInt32();
  },
  function (retval) {
    if (!this.$isTarget) return;
    const written = retval.toInt32();
    const hasPayload = written > 8 && this.bufferSize >= written;

    // 第一次调用只问长度（BufferSize=0），返回的是需要的字节数，没有内容可看。
    // 第二次才有真实数据；但默认不打印——表里就是完整机器码。
    let dump;
    if (!hasPayload) {
      dump = ' (仅询问长度)';
    } else if (CONFIG.dumpTable) {
      dump = ' 内容=' + preview(this.buffer, written, 320);
    } else {
      dump = ' (内容已省略；排错时把 CONFIG.dumpTable 改成 true)';
    }

    emit(
      'SMBIOS',
      '签名=' + this.signature + ' 表ID=0x' + this.tableId.toString(16) +
        ' 返回=' + written + dump + '   <- ' + this.$caller
    );
  }
);

hookExport(
  'ntdll.dll',
  'NtQuerySystemInformation',
  function (args) {
    this.infoClass = args[0].toUInt32();
  },
  function (retval) {
    if (!this.$isTarget) return;
    const names = {
      0x05: 'SystemProcessInformation',
      0x0b: 'SystemModuleInformation',
      0x4d: 'SystemFirmwareTableInformation',
    };
    const name = names[this.infoClass];
    if (!name) return;
    emit(
      'NTSYS',
      '类别=0x' + this.infoClass.toString(16) + ' (' + name + ') 状态=0x' +
        (retval.toInt32() >>> 0).toString(16) + '   <- ' + this.$caller
    );
  }
);

/* ------------------------------------------------------------------ */
/* 5. 网卡 MAC                                                         */
/* ------------------------------------------------------------------ */
/**
 * IP_ADAPTER_INFO 布局（x64）：
 *   Next(8) ComboIndex(4) AdapterName[260] Description[132] AddressLength(4) Address[8]
 * 所以物理地址长度在 0x8+0x4+260+132 = 404 偏移处。
 */
hookExport(
  'iphlpapi.dll',
  'GetAdaptersInfo',
  function (args) {
    this.buffer = args[0];
  },
  function (retval) {
    if (!this.$isTarget || retval.toInt32() !== 0 || !this.buffer || this.buffer.isNull()) return;
    let mac = '';
    try {
      const lengthOffset = 8 + 4 + 260 + 132;
      const length = this.buffer.add(lengthOffset).readU32();
      const address = this.buffer.add(lengthOffset + 4);
      const parts = [];
      for (let i = 0; i < Math.min(length, 8); i++) {
        parts.push(address.add(i).readU8().toString(16).padStart(2, '0'));
      }
      mac = parts.join(':');
    } catch (e) {}
    emit('NIC', 'MAC=' + mac + '   <- ' + this.$caller);
  }
);

hookExport(
  'iphlpapi.dll',
  'GetAdaptersAddresses',
  function () {},
  function (retval) {
    if (!this.$isTarget) return;
    emit('NIC', 'GetAdaptersAddresses 返回=' + retval.toInt32() + '   <- ' + this.$caller);
  }
);

/* ------------------------------------------------------------------ */
/* 6. 主机名 / 用户名                                                  */
/* ------------------------------------------------------------------ */
hookExport(
  'kernel32.dll',
  'GetComputerNameW',
  function (args) {
    this.buffer = args[0];
  },
  function (retval) {
    if (!this.$isTarget) return;
    const name = retval.toInt32() ? readUtf16(this.buffer) : '';
    emit('HOST', '计算机名=' + name + '   <- ' + this.$caller);
  }
);

hookExport(
  'kernel32.dll',
  'GetUserNameW',
  function (args) {
    this.buffer = args[0];
  },
  function (retval) {
    if (!this.$isTarget) return;
    const name = retval.toInt32() ? readUtf16(this.buffer) : '';
    emit('USER', '用户名=' + name + '   <- ' + this.$caller);
  }
);

/* ------------------------------------------------------------------ */
/* 7. WMI                                                              */
/* ------------------------------------------------------------------ */
/**
 * WMI 是拿硬件信息的另一条路（Win32_BaseBoard、Win32_DiskDrive…）。
 * 这里只记录 CLSID，够判断目标是否在用 WMI。
 */
const KNOWN_CLSIDS = {
  '4590f8111d3a11d0891f00aa004b2e24': 'WbemLocator',
  'd68af00a29cb43fa8504ce99b4c144da': 'WbemLocator.1',
  '8bc3f05e12c311d1a09a00c04fc2b090': 'WinMgmts',
};

/** 把 16 字节 GUID 转成常见字符串形式（去掉大小端混排的干扰，只用于对照表）。 */
function guidToString(ptr) {
  try {
    const b = new Uint8Array(ptr.readByteArray(16));
    const hex = Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
    return hex;
  } catch (e) {
    return '';
  }
}

hookExport(
  'ole32.dll',
  'CoCreateInstance',
  function (args) {
    this.clsid = guidToString(args[0]);
  },
  function (retval) {
    if (!this.$isTarget) return;
    const name = KNOWN_CLSIDS[this.clsid] || 'CLSID:' + this.clsid;
    emit('WMI', name + ' hr=0x' + (retval.toInt32() >>> 0).toString(16) + '   <- ' + this.$caller);
  }
);

/* ------------------------------------------------------------------ */
/* 8. 出站连接                                                         */
/* ------------------------------------------------------------------ */
/**
 * 记录所有 connect() 的目标地址。
 * 用途：确认反作弊的上报通道到底是 TCP 直连、本机代理，还是走游戏自身网络栈。
 * 注意这里不按目标模块过滤——我们想看到整个进程的连接全貌。
 */
hookExport(
  'ws2_32.dll',
  'connect',
  function (args) {
    this.sockaddr = args[1];
  },
  function (retval) {
    if (retval.toInt32() !== 0) return;
    try {
      if (!this.sockaddr || this.sockaddr.isNull()) return;
      if (this.sockaddr.readU16() !== 2) return; // 只看 IPv4（AF_INET=2）
      const port = (this.sockaddr.add(2).readU8() << 8) | this.sockaddr.add(3).readU8();
      const ip = [0, 1, 2, 3].map((i) => this.sockaddr.add(4 + i).readU8()).join('.');
      emit('CONN', ip + ':' + port + (this.$isTarget ? ' [目标]' : '') + '   <- ' + this.$caller);
    } catch (e) {}
  }
);

/* ------------------------------------------------------------------ */
/* 9. 模块加载                                                         */
/* ------------------------------------------------------------------ */
/**
 * 有些模块由 LdrLoadDll 直接加载，不经过 LoadLibrary，
 * 所以这里挂 ntdll 原生入口，同时保留 LoadLibraryExW 作为补充。
 */
hookExport(
  'ntdll.dll',
  'LdrLoadDll',
  function (args) {
    this.moduleName = '';
    try {
      const us = args[2]; // 第三个参数是指向 UNICODE_STRING 的指针
      const length = us.readU16();
      const buffer = us.add(8).readPointer();
      this.moduleName = length > 0 ? buffer.readUtf16String(length / 2) : '';
    } catch (e) {}
  },
  function (retval) {
    if (!this.moduleName) return;
    if (!/SL-AC|winhttp|wininet/i.test(this.moduleName)) return;
    emit('LOAD', 'LdrLoadDll ' + this.moduleName + ' 状态=0x' + (retval.toInt32() >>> 0).toString(16));
  }
);

hookExport(
  'kernel32.dll',
  'LoadLibraryExW',
  function (args) {
    this.path = readUtf16(args[0]);
  },
  function (retval) {
    if (!this.path || retval.isNull()) return;
    if (!/SL-AC|winhttp|wininet/i.test(this.path)) return;
    emit('LOAD', 'LoadLibraryExW ' + this.path);
  }
);

/* ------------------------------------------------------------------ */
/* 10. 定时快照                                                        */
/* ------------------------------------------------------------------ */
setTimeout(function () {
  try {
    const interesting = /SL-AC|GameAssembly|UnityPlayer|winhttp|wininet/i;
    Process.enumerateModules()
      .filter((m) => interesting.test(m.name))
      .forEach((m) =>
        emit('MOD', m.name + ' 基址=' + m.base + ' 大小=0x' + m.size.toString(16))
      );
  } catch (e) {}
}, 3000);

emit('READY', '侦察器已安装，目标模块=' + CONFIG.targetModule);
