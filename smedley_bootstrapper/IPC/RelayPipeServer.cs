using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Smedley.Bootstrapper.Models;

namespace Smedley.Bootstrapper.IPC
{

    public class RelayPipeServer
    {
        public event EventHandler? RelayReceived;

        public RelayPipeServer()
        {
        }

        public void Listen()
        {
            using var stream = new NamedPipeServerStream("smedley_launcher", PipeDirection.In);
            stream.WaitForConnection();
            using StreamReader sr = new(stream);

            string? line;
            try
            {
                while (true)
                {
                    line = sr.ReadLine();
                    if (line == null)
                    {
                        break;
                    }
                    if (line == "ready")
                    {
                        RelayReceived?.Invoke(this, EventArgs.Empty);
                    }
                }
            }
            catch (Exception exc)
            {
                Trace.WriteLine(exc.Message);
            }
        }
    }
}
