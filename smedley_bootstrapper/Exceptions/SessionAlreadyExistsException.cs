using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Smedley.Bootstrapper.Models;

namespace Smedley.Bootstrapper.Exceptions
{
    public class SessionAlreadyExistsException : Exception
    {
        public int ProcessID { get;  }
        public int ThreadID { get; }
        public string KernelModule { get; }

        public SessionAlreadyExistsException(Session session)
            : base(MakeMessage(session))
        {
            ProcessID = session.ProcessInfo.dwProcessId;
            ThreadID = session.ProcessInfo.dwThreadId;
            KernelModule = session.Settings.KernelPath;
        }

        private static string MakeMessage(Session session)
        {
            return "Session already exists! PID: " + session.ProcessInfo.dwProcessId + " Kernel Module: " + session.Settings.KernelPath;
        }
    }
}
