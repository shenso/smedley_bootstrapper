using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Diagnostics;

using Smedley.Bootstrapper.Binders;
using Smedley.Bootstrapper.Models;
using Smedley.Bootstrapper.IPC;

namespace Smedley.Bootstrapper.Commands
{
    public class BootCommand : ICommand
    {
        private MainBinder _binder;
        private bool _canExecute;

        public event EventHandler? CanExecuteChanged;

        public BootCommand(MainBinder binder)
        {
            _binder = binder;
            if (_binder.Session != null)
            {
                _canExecute = _binder.Session.Status == SessionStatus.ProcessClosed;
                _binder.Session.SessionStatusChange += OnSessionStatusChange;
            } else
            {
                _canExecute = true;
            }
        }

        private void OnSessionStatusChange(SessionStatus oldStatus, SessionStatus newStatus)
        {
            Application.Current.Dispatcher.Invoke(() => {
                var closed = newStatus == SessionStatus.ProcessClosed;
                if (closed && !_canExecute)
                {
                    _canExecute = true;
                    CanExecuteChanged?.Invoke(this, EventArgs.Empty);
                }
            });
        }

        public bool CanExecute(object? parameter)
        {
            return _canExecute;
        }

        public void Execute(object? parameter)
        {
            var appName = _binder.Settings.GameDirectoryPath + "\\" + "v2game.exe";

            if (_binder.Session != null && _binder.Session.Status != SessionStatus.ProcessClosed)
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
                if (_binder.Session != null)
                {
                    _binder.Session.SessionStatusChange -= OnSessionStatusChange;
                }
                _binder.Session = new Session(_binder.Settings);
                _binder.Session.SessionStatusChange += OnSessionStatusChange;
                _binder.Session.InjectKernel();

                if (_canExecute)
                {
                    _canExecute = false;
                    CanExecuteChanged?.Invoke(this, EventArgs.Empty);
                }
            }
            catch (Exception exc)
            {
                MessageBox.Show("Failed to create session: " + exc.Message);
            }
        }
    }
}
