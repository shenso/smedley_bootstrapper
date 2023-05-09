using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Input;
using Smedley.Bootstrapper.Commands;

namespace Smedley.Bootstrapper.Binders
{
    public class PathTextBoxBinder : Binder
    {
        private string _label = "";
        private string _path = "";

        public string Label { get { return _label; } set { SetProperty(ref _label, value); } }
        public string Path { get { return _path; } set { SetProperty(ref _path, value); } }

        public ICommand SelectPath { get; }

        public PathTextBoxBinder(string label = "", string path = "", bool isFolder = false)
        {
            _label = label;
            _path = path;
            if (isFolder)
            {
                SelectPath = new SelectFolderPathCommand(this);
            } else
            {
                SelectPath = new SelectFilePathCommand(this);
            }
        }
    }
}
