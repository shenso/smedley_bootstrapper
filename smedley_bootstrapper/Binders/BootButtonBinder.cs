using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using Smedley.Bootstrapper.Commands;
using Smedley.Bootstrapper.Models;
using Smedley.Bootstrapper.Exceptions;

namespace Smedley.Bootstrapper.Binders
{
    class BootButtonBinder : Binder
    {
        private Session? _session = null;
        private bool _isEnabled = true;

        public Session? Session
        {
            get { return _session; }
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

        public bool IsEnabled { get { return _isEnabled; } }

        public string Content
        {
            get
            {
                if (_session != null && _session.Status == SessionStatus.PendingThreadResume)
                {
                    return "Start Game";
                }

                return "Launch Game";
            }
        }

        public ICommand BootCommand { get; }

        public BootstrapSettings Settings { get; }

        public BootButtonBinder(BootstrapSettings settings)
        {
            Settings = settings;
            BootCommand = new DelegateCommand(OnClick, (object? o) => IsEnabled);
        }

        public void OnClick(object? parameter)
        {
            if (Session != null && Session.Status == SessionStatus.PendingThreadResume)
            {
                Session.ResumeGameThread();
            }
            else
            {
                BootSession();
            }
        }

        public void BootSession()
        {
            var appName = Settings.GameDirectoryPath + "\\" + "v2game.exe";

            if (Session != null && Session.Status != SessionStatus.ProcessClosed)
            {
                MessageBox.Show("Game is already running! Please exit the game before relaunching!");
                return;
            }

            if (!File.Exists(appName))
            {
                MessageBox.Show("Game does not exist at path " + appName);
                return;
            }

            try
            {
                if (Session != null)
                {
                    Session.SessionStatusChange -= OnSessionStatusChange;
                }
                Session = new Session(Settings);
                Session.SessionStatusChange += OnSessionStatusChange;
                Session.InjectKernel();
                Session.LoadPlugins();

                if (Session.Status == SessionStatus.ProcessRunning && _isEnabled)
                {
                    SetProperty(ref _isEnabled, false, "IsEnabled");
                }
            }
            catch (Exception exc)
            {
                MessageBox.Show("Failed to create session: " + exc.Message);
            }
        }

        private void OnSessionStatusChange(SessionStatus oldStatus, SessionStatus newStatus)
        {
            if (newStatus == SessionStatus.ProcessClosed && oldStatus != SessionStatus.ProcessRunning)
            {
                MessageBox.Show("Game unexpectedly stopped before smedley finished bootstrapping!");
            }

            bool enable = newStatus != SessionStatus.ProcessRunning;
            if (enable != _isEnabled)
            {
                SetProperty(ref _isEnabled, enable, "IsEnabled");
            }

            if (newStatus == SessionStatus.PendingThreadResume || oldStatus == SessionStatus.PendingThreadResume)
            {
                RaisePropertyChanged("Content");
            }
        }
    }
}
