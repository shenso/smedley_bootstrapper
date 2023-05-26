using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

using Smedley.Bootstrapper.Commands;
using Smedley.Bootstrapper.Exceptions;
using Smedley.Bootstrapper.Models;

namespace Smedley.Bootstrapper.Binders
{
    public class MainBinder : Binder
    {
        private Session? _session;
        private bool _canBoot = true;

        public BootstrapSettings Settings { get; }

        public Binder TargetViewBinder { get; }

        public Binder PluginViewBinder { get;  }

        public Session? Session
        {
            get { return _session;  }
            set
            {
                if (_session != null && _session.Status != SessionStatus.ProcessClosed)
                {
                    throw new SessionAlreadyExistsException(_session);
                }
                if (_session != null)
                {
                    _session.SessionStatusChange -= OnSessionStatusChange;
                }
                SetProperty(ref _session, value);
                if (_session != null)
                {
                    _session.SessionStatusChange += OnSessionStatusChange;
                }
            }
        }

        private void OnSessionStatusChange(SessionStatus oldStatus, SessionStatus newStatus)
        {
            if (newStatus == SessionStatus.ProcessClosed && oldStatus != SessionStatus.ProcessRunning)
            {
                MessageBox.Show("Game unexpectedly stopped before smedley finished bootstrapping!");
            }
        }

        public bool CanBootSession { get { return _canBoot; } }

        public ICommand BootSession { get; }

        public MainBinder()
        {
            var gameDir = BootstrapSettings.GetDefaultGameDirectory();
            var kernelPath = Path.Join(gameDir, "smedley_kernel.dll");
            if (!File.Exists(kernelPath))
            {
                kernelPath = "";
            }

            Settings = new BootstrapSettings(gameDir, kernelPath);
            TargetViewBinder = new BootstrapTargetViewBinder(Settings);
            PluginViewBinder = new PluginViewBinder(Settings);

            BootSession = new BootCommand(this);
            BootSession.CanExecuteChanged += (object sender, EventArgs e) =>
            {
                BootCommand command = (BootCommand) sender;
                if (_canBoot != command.CanExecute(null))
                {
                    _canBoot = command.CanExecute(null);
                    RaisePropertyChanged("CanBootSession");
                }
            };
        }
    }
}
