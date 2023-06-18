using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

using Smedley.Bootstrapper.Commands;
using Smedley.Bootstrapper.Exceptions;
using Smedley.Bootstrapper.Injector;

namespace Smedley.Bootstrapper.Models
{
    public enum SessionStatus
    {
        Started,
        WaitingForRelay,
        LoadingPlugins,
        ProcessRunning,
        ProcessClosed,
    }

    public delegate void SessionStatusChangeHandler(SessionStatus oldStatus, SessionStatus newStatus);

    public class Session
    {
        private SessionStatus _status;
        private object _lock = new object();

        private Injector.Injector _injector;

        public BootstrapSettings Settings { get; }

        public PROCESS_INFORMATION ProcessInfo { get; }

        public SessionStatus Status {
            get
            {
                lock (_lock)
                {
                    return _status;
                }
            }
            set
            {
                lock (_lock)
                {
                    if (_status != value)
                    {
                        var oldVal = _status;
                        _status = value;
                        SessionStatusChange?.Invoke(oldVal, value);
                    }
                }
            }
        }

        public event SessionStatusChangeHandler? SessionStatusChange;

        public Session(BootstrapSettings settings)
        {
            var appName = settings.GameDirectoryPath + "\\v2game.exe";
            var pSec = new SECURITY_ATTRIBUTES();
            var tSec = new SECURITY_ATTRIBUTES();
            var startupInfo = new STARTUPINFO();
            startupInfo.cb = Marshal.SizeOf(startupInfo);

            var success = Win32.CreateProcess(
                appName,
                settings.GetCommandLine(),
                ref pSec,
                ref tSec,
                true,
                Win32.CREATE_SUSPENDED,
                IntPtr.Zero,
                settings.GameDirectoryPath,
                ref startupInfo,
                out PROCESS_INFORMATION procInfo);

            if (!success)
            {
                throw new Exception("failed to create process");
            }

            ProcessInfo = procInfo;
            Settings = settings;
            _injector = new Injector.Injector(procInfo.hProcess);

            _status = SessionStatus.Started;

            //Task.Run(() => CommandPipe.Listen());
            Task.Run(() => WaitForProcessExit());
        }

        public void InjectKernel()
        {
            Status = SessionStatus.WaitingForRelay;
            _injector.Inject(Settings.KernelPath);
        }

        public void LoadPlugins()
        {
            Status = SessionStatus.LoadingPlugins;
            Trace.WriteLine("Loading plugins!");
            foreach (Plugin plugin in Settings.SelectedPlugins)
            {
                _injector.Inject(plugin.ModulePath);
                Trace.WriteLine("Plugin " + plugin.ModulePath + " injected!");
            }

            IntPtr kernelBase = Win32.GetModuleBaseEx(ProcessInfo.dwProcessId, "smedley_kernel.dll");
            Trace.WriteLine("Module base: " + kernelBase);
            IntPtr subroutine = Win32.GetProcAddressEx(ProcessInfo.hProcess, kernelBase, "LoadPlugins");
            if (subroutine != IntPtr.Zero)
            {
                Trace.WriteLine("LoadPlugins: " + subroutine);
                var loadPluginsThread = Win32.CreateRemoteThread(ProcessInfo.hProcess, IntPtr.Zero, 0, subroutine, IntPtr.Zero, 0, out IntPtr lpThreadId);
                Trace.WriteLine("Load plugins thread id: " + lpThreadId);
                Win32.WaitForSingleObject(loadPluginsThread, Win32.INFINITE);
            }
            else
            {
                Trace.WriteLine("failed to find loadplugins func");
            }

            ResumeGameThread();
        }

        private void ResumeGameThread()
        {
            Win32.ResumeThread(ProcessInfo.hThread);
            Status = SessionStatus.ProcessRunning;
        }

        private void WaitForProcessExit()
        {
            Win32.WaitForSingleObject(ProcessInfo.hProcess, Win32.INFINITE);
            Status = SessionStatus.ProcessClosed;
        }
    }
}
