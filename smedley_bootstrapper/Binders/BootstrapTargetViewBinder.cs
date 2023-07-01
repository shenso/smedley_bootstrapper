using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Smedley.Bootstrapper.Models;

namespace Smedley.Bootstrapper.Binders
{
    public class BootstrapTargetViewBinder : Binder
    {
        public BootstrapSettings BootstrapSettings { get; }
        public PathTextBoxBinder GameDirBinder { get; }
        public PathTextBoxBinder KernelPathBinder { get; }

        public event Action? GameDirectoryChanged;

        public BootstrapTargetViewBinder(BootstrapSettings settings)
        {
            BootstrapSettings = settings;
            GameDirBinder = new PathTextBoxBinder("Game Directory:", settings.GameDirectoryPath, true);
            KernelPathBinder = new PathTextBoxBinder("Kernel Path:", settings.KernelPath, false);

            GameDirBinder.PropertyChanged += OnGameDirBinderChanged;
            KernelPathBinder.PropertyChanged += OnKernelPathBinderChanged;
        }

        private void OnGameDirBinderChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == "Path" && sender != null)
            {
                BootstrapSettings.GameDirectoryPath = ((PathTextBoxBinder)sender).Path;

                var gameDir = BootstrapSettings.GameDirectoryPath;
                var kernelPath = Path.Join(gameDir, "smedley_kernel.dll");
                if (File.Exists(kernelPath))
                {
                    KernelPathBinder.Path = kernelPath;
                }
                GameDirectoryChanged?.Invoke();
            }
        }

        private void OnKernelPathBinderChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == "Path" && sender != null)
            {
                BootstrapSettings.KernelPath = ((PathTextBoxBinder) sender).Path;
            }
        }
    }
}
