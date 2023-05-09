using System;
using System.IO;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

using Smedley.Bootstrapper.Exceptions;
using Smedley.Bootstrapper.Injector;
using Smedley.Bootstrapper.IPC;

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

        public BootstrapSettings Settings { get; }

        public PROCESS_INFORMATION ProcessInfo { get; }

        public RelayPipeServer RelayPipe { get; }

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
                appName, // TODO: support mod selection
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
            RelayPipe = new RelayPipeServer();
            RelayPipe.RelayReceived += OnRelayReceived;

            _status = SessionStatus.Started;

            Task.Run(() => RelayPipe.Listen());
            Task.Run(() => WaitForProcessExit());
        }

        public void InjectKernel()
        {
            var injector = new Injector.Injector(ProcessInfo.hProcess);
            Status = SessionStatus.WaitingForRelay;
            injector.Inject(Settings.KernelPath);
        }

        private void OnRelayReceived(object? sender, EventArgs e)
        {
            if (Status != SessionStatus.WaitingForRelay)
            {
                throw new InvalidOperationException("unexpected relay received!");
            }

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
