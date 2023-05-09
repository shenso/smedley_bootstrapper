using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Smedley.Bootstrapper.Injector
{
    public class Injector
    {
        private IntPtr _hProcess;

        public Injector(IntPtr hProcess)
        {
            _hProcess = hProcess;
        }

        public IntPtr Inject(string modulePath)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(modulePath);
            bytes = bytes.Concat(new byte[] { 0x0 }).ToArray();

            var buf = Win32.VirtualAllocEx(_hProcess, IntPtr.Zero, (uint) bytes.Length, (uint) AllocationType.Commit, (uint) MemoryProtection.ReadWrite);
            Win32.WriteProcessMemory(_hProcess, buf, bytes, bytes.Length, out IntPtr bytesWritten);
            var subroutine = Win32.GetProcAddress(Win32.GetModuleHandle("Kernel32"), "LoadLibraryA");
            return Win32.CreateRemoteThread(_hProcess, IntPtr.Zero, 0, subroutine, buf, 0, out IntPtr lpThreadId);
        }
    }
}
