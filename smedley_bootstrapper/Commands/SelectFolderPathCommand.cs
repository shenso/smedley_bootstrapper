using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;

using Smedley.Bootstrapper.Binders;

namespace Smedley.Bootstrapper.Commands
{
    public class SelectFolderPathCommand : ICommand
    {
        private PathTextBoxBinder _binder;

        public event EventHandler? CanExecuteChanged;

        public SelectFolderPathCommand(PathTextBoxBinder binder)
        {
            _binder = binder;
        }

        public bool CanExecute(object? parameter)
        {
            return true;
        }

        public void Execute(object? parameter)
        {
            using var dialog = new System.Windows.Forms.FolderBrowserDialog();

            dialog.SelectedPath = _binder.Path;
            dialog.ShowNewFolderButton = false;

            var result = dialog.ShowDialog();
            if (result == System.Windows.Forms.DialogResult.OK)
            {
                _binder.Path = dialog.SelectedPath;
            }
        }
    }
}
