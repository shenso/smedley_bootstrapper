using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Linq;

namespace Smedley.Bootstrapper
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public unsafe byte* lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER
    {
        public UInt16 Machine;
        public UInt16 NumberOfSections;
        public UInt32 TimeDateStamp;
        public UInt32 PointerToSymbolTable;
        public UInt32 NumberOfSymbols;
        public UInt16 SizeOfOptionalHeader;
        public UInt16 Characteristics;
    }

    public enum MachineType : ushort
    {
        /// <summary>
        /// The content of this field is assumed to be applicable to any machine type
        /// </summary>
        Unknown = 0x0000,
        /// <summary>
        /// Intel 386 or later processors and compatible processors
        /// </summary>
        I386 = 0x014c,
        R3000 = 0x0162,
        /// <summary>
        ///  MIPS little endian
        /// </summary>
        R4000 = 0x0166,
        R10000 = 0x0168,
        /// <summary>
        /// MIPS little-endian WCE v2
        /// </summary>
        WCEMIPSV2 = 0x0169,
        /// <summary>
        /// Alpha AXP
        /// </summary>
        Alpha = 0x0184,
        /// <summary>
        /// Hitachi SH3
        /// </summary>
        SH3 = 0x01a2,
        /// <summary>
        /// Hitachi SH3 DSP
        /// </summary>
        SH3DSP = 0x01a3,
        /// <summary>
        /// Hitachi SH4
        /// </summary>
        SH4 = 0x01a6,
        /// <summary>
        /// Hitachi SH5
        /// </summary>
        SH5 = 0x01a8,
        /// <summary>
        /// ARM little endian
        /// </summary>
        ARM = 0x01c0,
        /// <summary>
        /// Thumb
        /// </summary>
        Thumb = 0x01c2,
        /// <summary>
        /// ARM Thumb-2 little endian
        /// </summary>
        ARMNT = 0x01c4,
        /// <summary>
        /// Matsushita AM33
        /// </summary>
        AM33 = 0x01d3,
        /// <summary>
        /// Power PC little endian
        /// </summary>
        PowerPC = 0x01f0,
        /// <summary>
        /// Power PC with floating point support
        /// </summary>
        PowerPCFP = 0x01f1,
        /// <summary>
        /// Intel Itanium processor family
        /// </summary>
        IA64 = 0x0200,
        /// <summary>
        /// MIPS16
        /// </summary>
        MIPS16 = 0x0266,
        /// <summary>
        /// Motorola 68000 series
        /// </summary>
        M68K = 0x0268,
        /// <summary>
        /// Alpha AXP 64-bit
        /// </summary>
        Alpha64 = 0x0284,
        /// <summary>
        /// MIPS with FPU
        /// </summary>
        MIPSFPU = 0x0366,
        /// <summary>
        /// MIPS16 with FPU
        /// </summary>
        MIPSFPU16 = 0x0466,
        /// <summary>
        /// EFI byte code
        /// </summary>
        EBC = 0x0ebc,
        /// <summary>
        /// RISC-V 32-bit address space
        /// </summary>
        RISCV32 = 0x5032,
        /// <summary>
        /// RISC-V 64-bit address space
        /// </summary>
        RISCV64 = 0x5064,
        /// <summary>
        /// RISC-V 128-bit address space
        /// </summary>
        RISCV128 = 0x5128,
        /// <summary>
        /// x64
        /// </summary>
        AMD64 = 0x8664,
        /// <summary>
        /// ARM64 little endian
        /// </summary>
        ARM64 = 0xaa64,
        /// <summary>
        /// LoongArch 32-bit processor family
        /// </summary>
        LoongArch32 = 0x6232,
        /// <summary>
        /// LoongArch 64-bit processor family
        /// </summary>
        LoongArch64 = 0x6264,
        /// <summary>
        /// Mitsubishi M32R little endian
        /// </summary>
        M32R = 0x9041
    }
    public enum MagicType : ushort
    {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
    }
    public enum SubSystemType : ushort
    {
        IMAGE_SUBSYSTEM_UNKNOWN = 0,
        IMAGE_SUBSYSTEM_NATIVE = 1,
        IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
        IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
        IMAGE_SUBSYSTEM_POSIX_CUI = 7,
        IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
        IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
        IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
        IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
        IMAGE_SUBSYSTEM_EFI_ROM = 13,
        IMAGE_SUBSYSTEM_XBOX = 14

    }
    public enum DllCharacteristicsType : ushort
    {
        RES_0 = 0x0001,
        RES_1 = 0x0002,
        RES_2 = 0x0004,
        RES_3 = 0x0008,
        IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
        IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
        IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
        IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
        IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
        IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
        RES_4 = 0x1000,
        IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
        IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        [FieldOffset(0)]
        public MagicType Magic;

        [FieldOffset(2)]
        public byte MajorLinkerVersion;

        [FieldOffset(3)]
        public byte MinorLinkerVersion;

        [FieldOffset(4)]
        public uint SizeOfCode;

        [FieldOffset(8)]
        public uint SizeOfInitializedData;

        [FieldOffset(12)]
        public uint SizeOfUninitializedData;

        [FieldOffset(16)]
        public uint AddressOfEntryPoint;

        [FieldOffset(20)]
        public uint BaseOfCode;

        // PE32 contains this additional field
        [FieldOffset(24)]
        public uint BaseOfData;

        [FieldOffset(28)]
        public uint ImageBase;

        [FieldOffset(32)]
        public uint SectionAlignment;

        [FieldOffset(36)]
        public uint FileAlignment;

        [FieldOffset(40)]
        public ushort MajorOperatingSystemVersion;

        [FieldOffset(42)]
        public ushort MinorOperatingSystemVersion;

        [FieldOffset(44)]
        public ushort MajorImageVersion;

        [FieldOffset(46)]
        public ushort MinorImageVersion;

        [FieldOffset(48)]
        public ushort MajorSubsystemVersion;

        [FieldOffset(50)]
        public ushort MinorSubsystemVersion;

        [FieldOffset(52)]
        public uint Win32VersionValue;

        [FieldOffset(56)]
        public uint SizeOfImage;

        [FieldOffset(60)]
        public uint SizeOfHeaders;

        [FieldOffset(64)]
        public uint CheckSum;

        [FieldOffset(68)]
        public SubSystemType Subsystem;

        [FieldOffset(70)]
        public DllCharacteristicsType DllCharacteristics;

        [FieldOffset(72)]
        public uint SizeOfStackReserve;

        [FieldOffset(76)]
        public uint SizeOfStackCommit;

        [FieldOffset(80)]
        public uint SizeOfHeapReserve;

        [FieldOffset(84)]
        public uint SizeOfHeapCommit;

        [FieldOffset(88)]
        public uint LoaderFlags;

        [FieldOffset(92)]
        public uint NumberOfRvaAndSizes;

        [FieldOffset(96)]
        public IMAGE_DATA_DIRECTORY ExportTable;

        [FieldOffset(104)]
        public IMAGE_DATA_DIRECTORY ImportTable;

        [FieldOffset(112)]
        public IMAGE_DATA_DIRECTORY ResourceTable;

        [FieldOffset(120)]
        public IMAGE_DATA_DIRECTORY ExceptionTable;

        [FieldOffset(128)]
        public IMAGE_DATA_DIRECTORY CertificateTable;

        [FieldOffset(136)]
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;

        [FieldOffset(144)]
        public IMAGE_DATA_DIRECTORY Debug;

        [FieldOffset(152)]
        public IMAGE_DATA_DIRECTORY Architecture;

        [FieldOffset(160)]
        public IMAGE_DATA_DIRECTORY GlobalPtr;

        [FieldOffset(168)]
        public IMAGE_DATA_DIRECTORY TLSTable;

        [FieldOffset(176)]
        public IMAGE_DATA_DIRECTORY LoadConfigTable;

        [FieldOffset(184)]
        public IMAGE_DATA_DIRECTORY BoundImport;

        [FieldOffset(192)]
        public IMAGE_DATA_DIRECTORY IAT;

        [FieldOffset(200)]
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

        [FieldOffset(208)]
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

        [FieldOffset(216)]
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public char[] e_magic;       // Magic number
        public UInt16 e_cblp;    // Bytes on last page of file
        public UInt16 e_cp;      // Pages in file
        public UInt16 e_crlc;    // Relocations
        public UInt16 e_cparhdr;     // Size of header in paragraphs
        public UInt16 e_minalloc;    // Minimum extra paragraphs needed
        public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
        public UInt16 e_ss;      // Initial (relative) SS value
        public UInt16 e_sp;      // Initial SP value
        public UInt16 e_csum;    // Checksum
        public UInt16 e_ip;      // Initial IP value
        public UInt16 e_cs;      // Initial (relative) CS value
        public UInt16 e_lfarlc;      // File address of relocation table
        public UInt16 e_ovno;    // Overlay number
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public UInt16[] e_res1;    // Reserved words
        public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
        public UInt16 e_oeminfo;     // OEM information; e_oemid specific
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public UInt16[] e_res2;    // Reserved words
        public Int32 e_lfanew;      // File address of new exe header

        private string _e_magic
        {
            get { return new string(e_magic); }
        }

        public bool isValid
        {
            get { return _e_magic == "MZ"; }
        }
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_NT_HEADERS32
    {
        [FieldOffset(0)]
        public UInt32 Signature;

        [FieldOffset(4)]
        public IMAGE_FILE_HEADER FileHeader;

        [FieldOffset(24)]
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader;

        private string _Signature
        {
            get { return Encoding.ASCII.GetString(BitConverter.GetBytes(Signature)); }
        }

        public bool isValid
        {
            get { return _Signature == "PE\0\0" && OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR32_MAGIC; }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_EXPORT_DIRECTORY
    {
        public UInt32 Characteristics;
        public UInt32 TimeDateStamp;
        public UInt16 MajorVersion;
        public UInt16 MinorVersion;
        public UInt32 Name;
        public UInt32 Base;
        public UInt32 NumberOfFunctions;
        public UInt32 NumberOfNames;
        public UInt32 AddressOfFunctions;     // RVA from base of image
        public UInt32 AddressOfNames;     // RVA from base of image
        public UInt32 AddressOfNameOrdinals;  // RVA from base of image
    }

    [StructLayout(LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    public struct MODULEENTRY32
    {
        internal uint dwSize;
        internal uint th32ModuleID;
        internal uint th32ProcessID;
        internal uint GlblcntUsage;
        internal uint ProccntUsage;
        internal IntPtr modBaseAddr;
        internal uint modBaseSize;
        internal IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        internal string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string szExePath;
    }

    [Flags]
    public enum AllocationType : uint
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        LargePages = 0x20000000
    }

    [Flags]
    public enum MemoryProtection : uint
    {
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        GuardModifierflag = 0x100,
        NoCacheModifierflag = 0x200,
        WriteCombineModifierflag = 0x400
    }

    [Flags]
    public enum SnapshotFlags : uint
    {
        HeapList = 0x00000001,
        Process = 0x00000002,
        Thread = 0x00000004,
        Module = 0x00000008,
        Module32 = 0x00000010,
        All = (HeapList | Process | Thread | Module),
        Inherit = 0x80000000,
        NoHeaps = 0x40000000

    }

    public class Win32
    {
        public const UInt32 CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
        public const UInt32 CREATE_DEFAULT_ERROR_MODE = 0x04000000;
        public const UInt32 CREATE_NEW_CONSOLE = 0x00000010;
        public const UInt32 CREATE_NEW_PROCESS_GROUP = 0x00000200;
        public const UInt32 CREATE_NO_WINDOW = 0x08000000;
        public const UInt32 CREATE_PROTECTED_PROCESS = 0x00040000;
        public const UInt32 CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000;
        public const UInt32 CREATE_SECURE_PROCESS = 0x00400000;
        public const UInt32 CREATE_SEPARATE_WOW_VDM = 0x00000800;
        public const UInt32 CREATE_SHARED_WOW_VDM = 0x00001000;
        public const UInt32 CREATE_SUSPENDED = 0x00000004;
        public const UInt32 CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        public const UInt32 DEBUG_ONLY_THIS_PROCESS = 0x00000002;
        public const UInt32 DEBUG_PROCESS = 0x00000001;
        public const UInt32 DETACHED_PROCESS = 0x00000008;
        public const UInt32 EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        public const UInt32 INHERIT_PARENT_AFFINITY = 0x00010000;

        public const UInt32 INFINITE = 0xFFFFFFFF;
        public const UInt32 WAIT_ABANDONED = 0x00000080;
        public const UInt32 WAIT_OBJECT_0 = 0x00000000;
        public const UInt32 WAIT_TIMEOUT = 0x00000102;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcess(
           string lpApplicationName,
           string lpCommandLine,
           ref SECURITY_ATTRIBUTES lpProcessAttributes,
           ref SECURITY_ATTRIBUTES lpThreadAttributes,
           bool bInheritHandles,
           uint dwCreationFlags,
           IntPtr lpEnvironment,
           string lpCurrentDirectory,
           [In] ref STARTUPINFO lpStartupInfo,
           out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private unsafe static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            void *lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [MarshalAs(UnmanagedType.AsAny)] object lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess,
           IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
           IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("psapi.dll", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern bool EnumProcessModules(IntPtr hProcess, [In][Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

        [DllImport("psapi.dll")]
        public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In][MarshalAs(UnmanagedType.U4)] int nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, int th32ProcessID);

        [DllImport("kernel32.dll")]
        public static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll")]
        public static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll")]
        public static extern int GetProcessId(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        public static IntPtr GetProcModuleHandle(IntPtr hProcess, string modName)
        {
            IntPtr[] hMods = new IntPtr[1024];
            IntPtr hMod = IntPtr.Zero;

            EnumProcessModules(hProcess, hMods, (uint) (Marshal.SizeOf(typeof(IntPtr)) * hMods.Length), out uint bytesNeeded);
            for (int i = 0; i < bytesNeeded / Marshal.SizeOf(typeof(IntPtr)) && i < hMods.Length; i++)
            {
                StringBuilder sb = new StringBuilder(1024);
                GetModuleFileNameEx(hProcess, hMods[i], sb, sb.Capacity);

                var name = Path.GetFileName(sb.ToString());
                if (name == modName)
                {
                    hMod = hMods[i];
                    break;
                }
            }

            return hMod;
        }

        public static IntPtr GetModuleBaseEx(int processId, string modName)
        {
            var modules = Process.GetProcessById(processId).Modules;
            foreach (ProcessModule mod in modules)
            {
                if (Path.GetFileName(mod.ModuleName) == modName)
                {
                    return mod.BaseAddress;
                }
            }

            return IntPtr.Zero;
        }

        public static bool ReadProcessMemory<T>(IntPtr hProcess, IntPtr addr, out T val)
        {
            byte[] buf = new byte[Marshal.SizeOf(typeof(T))];
            if (!ReadProcessMemory(hProcess, addr, buf, buf.Length, out _))
            {
                val = default(T);
                return false;
            }

            var handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
            val = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            return true;
        }

        public static IntPtr GetProcAddressEx(IntPtr hProcess, IntPtr modBase, string funcName)
        {
            IMAGE_DOS_HEADER dosHeader = new();
            IMAGE_NT_HEADERS32 ntHeaders = new();
            IMAGE_EXPORT_DIRECTORY exports = new();

            if (!ReadProcessMemory(hProcess, modBase, out dosHeader))
                return IntPtr.Zero;


            if (!ReadProcessMemory(hProcess, modBase + dosHeader.e_lfanew, out ntHeaders))
                return IntPtr.Zero;

            var addr = ntHeaders.OptionalHeader.ExportTable.VirtualAddress;
            if (!ReadProcessMemory(hProcess, (IntPtr)((uint)modBase + addr), out exports))
                return IntPtr.Zero;

            var funcAddrs = (uint) modBase + exports.AddressOfFunctions;
            var nameAddrs = (uint) modBase + exports.AddressOfNames;
            var ordinalAddrs = (uint)modBase + exports.AddressOfNameOrdinals;

            for (int i = 0; i < exports.NumberOfNames; i++)
            {
                IntPtr nameAddr = IntPtr.Zero;
                byte[] buf = new byte[4096];

                if (!ReadProcessMemory(hProcess, (IntPtr)(nameAddrs + (i * Marshal.SizeOf(typeof(IntPtr)))), out nameAddr))
                    return IntPtr.Zero;

                if (!ReadProcessMemory(hProcess, (IntPtr) ((uint) modBase + (uint) nameAddr), buf, Marshal.SizeOf(typeof(byte)) * 1024, out IntPtr _))
                    return IntPtr.Zero;

                buf = buf.TakeWhile(b => b != 0x0).ToArray();
                string name = Encoding.ASCII.GetString(buf);
                if (name == funcName)
                {
                    IntPtr fn = IntPtr.Zero;
                    ushort ordinal = 0;

                    if (!ReadProcessMemory(hProcess, (IntPtr) (ordinalAddrs + (i * Marshal.SizeOf(typeof(ushort)))), out ordinal))
                        return IntPtr.Zero;
                    if (!ReadProcessMemory(hProcess, (IntPtr) (funcAddrs + (ordinal * Marshal.SizeOf(typeof(IntPtr)))), out fn))
                        return IntPtr.Zero;

                    return (IntPtr) ((uint) modBase + (uint) fn);
                }
            }

            return IntPtr.Zero;
        }

    }


}