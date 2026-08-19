<div align="center">

# SII Decrypt (C++)

*已停更的 Pascal 项目 [SII_Decrypt](https://github.com/TheLazyTomcat/SII_Decrypt)(作者 TheLazyTomcat)的 C++ 重写版,并在此基础上增加了对新版游戏的支持。*

![Version](https://img.shields.io/badge/version-1.5.3-blue)
![Language](https://img.shields.io/badge/language-C%2B%2B11-f34b7d)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Games](https://img.shields.io/badge/games-ETS2%20%7C%20ATS-orange)
![API](https://img.shields.io/badge/DLL%20API-v1.1-9cf)

Languages: **简体中文** | [English](README.md)

</div>

SII Decrypt 可以把**欧洲卡车模拟 2**(Euro Truck Simulator 2)和**美洲卡车模拟**(American Truck Simulator)的存档文件转换为可读的纯文本 SII,便于查看、编辑以及配合各类存档工具使用。

---

## 目录

- [特性](#特性)
- [支持的格式](#支持的格式)
- [工作原理](#工作原理)
- [编译](#编译)
- [命令行用法](#命令行用法)
- [DLL / C API](#dll--c-api)
- [项目结构](#项目结构)
- [致谢](#致谢)
- [许可证](#许可证)

---

## 特性

- **自动识别格式** —— 自动识别 `SiiN`、`ScsC`、`3nK#01` 和 `BSII`
- **AES-256-CBC 解密** —— 自包含实现,无需 OpenSSL
- **BSII 二进制解码** —— 本项目新增,支持游戏 1.45 及以后版本的二进制存档
- **3nK 解码** —— 基于 256 字节密钥表的 XOR 解码
- **零依赖** —— 手写 AES 与 DEFLATE,完全静态链接
- **控制台 + DLL** —— 命令行工具 + C 兼容 DLL(API v1.1,可直接替代原 Pascal DLL)

---

## 支持的格式

游戏在历次更新中多次更换过存档格式。本工具会自动识别格式,并全部支持:

| 签名 | 格式 | 处理方式 |
|-----------|--------|----------|
| `SiiN` | 纯文本 SII | 原样输出 |
| `ScsC` | 加密 SII | AES-256-CBC 解密 + zlib 解压 |
| `3nK#01` | 3nK 编码 SII | 用 256 字节密钥表做 XOR 解码 |
| `BSII` | 二进制 SII(版本 1–3) | 解析并转换为文本 |

## 工作原理

存档文件(如 `game.sii`)的处理流水线如下:

```
加密文件 (.sii)
  │  56 字节 "ScsC" 头:Signature + HMAC[32] + IV[16] + DataSize
  ▼
AES-256-CBC 解密(PKCS#7 去填充)
  ▼
zlib / DEFLATE 解压
  ▼
内部格式识别
  ├─ "3nK#01" ──► 3nK 解码(与 KeyTable[(seed + pos) % 256] 做 XOR)
  ├─ "BSII"   ──► 二进制 SII 解码 → 文本
  └─ "SiiN"   ──► 已经是纯文本
  ▼
可读的 SII 文本
```

所有功能**完全自包含**:AES-256 实现、DEFLATE(RFC 1950/1951)解压器、3nK 解码器和 BSII 解析器均为从零实现 —— 不依赖 OpenSSL、zlib 或任何外部库。

## 编译

环境要求:

- **MinGW-w64**(`g++`,支持 32 位目标,i686)
- **GNU Make**

### 32 位编译

本项目**有意构建为 32 位**二进制(Makefile 中默认设置了 `-m32`),除非有特殊原因,请保持 32 位:

- 原 Pascal 版 `SII_Decrypt.dll` 是 32 位的,保持相同目标架构可以让本 DLL 作为它的直接替代品,现有工具无需修改即可加载。
- 作为 32 位二进制,控制台程序和 DLL 在 64 位 Windows 上依然完全可用,同时避免与 32 位宿主工具不匹配的问题。

Makefile 通过 `mingw32` 变量定位工具链目录,该变量未在文件内定义,构建时请在命令行传入(或编辑 Makefile 直接写入):

```bat
mingw32-make all mingw32=C:\Tools\mingw32\bin
```

构建目标:

| 目标 | 产物 |
|--------|--------|
| `make all` | `build\sii_decrypt.dll` + `build\sii_decrypt.exe` |
| `make dll` | `build\sii_decrypt.dll`(+导入库 `libsii_decrypt.a`) |
| `make console` | `build\sii_decrypt.exe` |
| `make clean` | 清理构建产物 |

两个二进制文件均为完全静态、去除符号的版本(不需要 MinGW 运行时 DLL)。

## 命令行用法

```
SII_Decrypt.exe InputFile [OutputFile]
SII_Decrypt.exe [commands] -i InputFile [-o OutputFile]
```

如果不指定输出文件,解密结果会**覆盖输入文件**。

**命令:**

| 命令 | 作用 |
|---------|--------|
| `--no_decode` | 只解密,跳过 3nK / BSII 解码 |
| `--wait` | 处理完成后等待按键 |

**示例:**

```bat
REM 解密并解码,覆盖原文件
sii_decrypt.exe "C:\Users\me\Documents\Euro Truck Simulator 2\profiles\4D61696E\save\1\game.sii"

REM 将结果写入单独的文件
sii_decrypt.exe -i "game.sii" -o "game_decrypted.sii"

REM 只解密,保留 3nK 编码后的数据
sii_decrypt.exe --no_decode -i "game.sii" -o "game_decrypted_only.sii"
```

存档文件位于:

```
%USERPROFILE%\Documents\Euro Truck Simulator 2\profiles\<profile>\save\<id>\
%USERPROFILE%\Documents\American Truck Simulator\profiles\<profile>\save\<id>\
```

## DLL / C API

DLL 导出了与原 Pascal 版 `SII_Decrypt.dll` 相同的 C API(API 版本 1.1),并增加了新函数。任何支持 `__stdcall` C 导出的语言都可以调用 —— C、C++、Delphi/Lazarus、C# 等。

完整的 API 文档见 [include/sii_decrypt.h](include/sii_decrypt.h)。

### 独立函数

```c
#include "sii_decrypt.h"

/* 检测文件内容 */
int32_t fmt = GetFileFormat("game.sii");
/* 1 = 纯文本,2 = 加密,3 = 二进制,4 = 3nK,10 = 未知 */

/* 快速判断 */
if (IsEncryptedFile("game.sii"))   { /* ... */ }
if (Is3nKEncodedFile("game.sii"))  { /* ... */ }

/* 一步完成解密 + 解码并写入文件 */
int32_t res = DecryptAndDecodeFile("game.sii", "game_decrypted.sii");
```

基于内存的函数(`DecryptMemory`、`DecodeMemory`、`DecryptAndDecodeMemory`)采用**两遍调用**协议:先以 `Output = NULL` 调用一次查询所需缓冲区大小,分配内存后再带着缓冲区调用第二次。`...MemoryHelper` 变体额外提供一个不透明的 helper 对象,使第二遍不必重复解码工作 —— 如果中途放弃,必须调用 `FreeHelper()` 释放。

### 对象式 API(v1.1)

另提供与 Pascal 原版一致的对象式 API:

```c
TSIIDecryptorObject dec = Decryptor_Create();

Decryptor_SetOptionBool(dec, SIIDEC_OPTIONID_ACCEL_AES, 1);   /* 默认启用 */
Decryptor_SetOptionBool(dec, SIIDEC_OPTIONID_DEC_UNSUPP, 0);  /* 解码不支持的 BSII 值 */
Decryptor_SetProgressCallback(dec, MyProgressCallback);       /* 进度范围 [0.0, 1.0] */

int32_t res = Decryptor_DecryptAndDecodeFile(dec, "game.sii", "game_decrypted.sii");

Decryptor_Free(&dec);
```

### 返回码

| 返回码 | 含义 |
|------|---------|
| `0` | 成功 |
| `1` | 数据是纯文本 SII(无需解密) |
| `2` | 数据是加密 SII |
| `3` | 数据是二进制 SII |
| `4` | 数据是 3nK 编码 |
| `10` | 未知格式 |
| `11` | 数据太少,不足以构成有效格式 |
| `12` | 输出缓冲区太小 |
| `-1` | 一般性错误 |

## 项目结构

```
SII-Decrypt-cpp/
├── include/
│   └── sii_decrypt.h          公共 C API 头文件(DLL 导出)
├── src/
│   ├── core/
│   │   ├── sii_types.h        共享类型、签名、返回码
│   │   ├── sii_format.cpp/.h  格式检测、AES+DEFLATE 步骤、3nK 解码
│   │   ├── sii_decryptor.cpp/.h  高层 SIIDecryptor 类
│   │   ├── sii_bin_types.h    BSII 结构与值类型
│   │   ├── sii_bin_utils.*    解析辅助函数
│   │   ├── sii_bin_value.*    值解码
│   │   ├── sii_bin_data.*     数据块解析
│   │   └── sii_bin_decoder.*  入口:BSII 缓冲区 → 文本
│   ├── crypto/
│   │   └── aes256.cpp/.h      自包含 AES-256-CBC 解密
│   ├── compress/
│   │   └── inflate.cpp/.h     极简 zlib/DEFLATE 解压器(RFC 1950/1951)
│   ├── sii_console.cpp        控制台程序
│   ├── sii_dll.cpp            DLL 入口点(C API 封装)
│   └── sii_decrypt.def        DLL 导出定义
├── Makefile                   MinGW 构建(DLL + 控制台,零依赖)
└── LICENSE                    MIT 许可证
```

## 致谢

- [TheLazyTomcat](https://github.com/TheLazyTomcat) —— 原 Pascal 版 [SII_Decrypt](https://github.com/TheLazyTomcat/SII_Decrypt) 项目的作者,本移植版沿用了它的 API 与行为。

## 许可证

[MIT 许可证](LICENSE) —— 版权所有 (c) 2026 Liam Dong。

本项目是独立的社区工具,与 SCS Software 无关,亦未获其认可。
