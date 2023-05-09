using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

using Smedley.Bootstrapper.Binders;

namespace Smedley.Bootstrapper.Commands
{
    public class SelectFilePathCommand : ICommand
    {
        private PathTextBoxBinder _binder;

        public event EventHandler? CanExecuteChanged;

        public SelectFilePathCommand(PathTextBoxBinder binder)
        {
            _binder = binder;
        }

        public bool CanExecute(object? parameter)
        {
            return true;
        }

        public void Execute(object? parameter)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                FileName = _binder.Path,
                DefaultExt = ".dll",
                Filter = "Dynamic link libraries (.dll)|*.dll"
            };

            var result = dialog.ShowDialog();
            if (result == true)
            {
                _binder.Path = dialog.FileName;
            }
        }
    }
}
