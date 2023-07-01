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
using Smedley.Bootstrapper.Models;

namespace Smedley.Bootstrapper.Binders
{
    public class MainBinder : Binder
    {
        public BootstrapSettings Settings { get; }

        public Binder TargetViewBinder { get; }

        public PluginViewBinder PluginViewBinder { get;  }
        
        public Binder SettingsBinder { get; }

        public Binder BootButtonBinder { get; }

        public MainBinder()
        {
            var gameDir = BootstrapSettings.GetDefaultGameDirectory();
            var kernelPath = Path.Join(gameDir, "smedley_kernel.dll");
            if (!File.Exists(kernelPath))
            {
                kernelPath = "";
            }

            Settings = new BootstrapSettings(gameDir, kernelPath);

            var targetViewBinder = new BootstrapTargetViewBinder(Settings);
            TargetViewBinder = targetViewBinder;
            PluginViewBinder = new PluginViewBinder(Settings);
            SettingsBinder = new SettingsBinder(Settings);
            BootButtonBinder = new BootButtonBinder(Settings);

            targetViewBinder.GameDirectoryChanged += OnGameDirectoryChanged;
        }

        private void OnGameDirectoryChanged()
        {
            PluginViewBinder.Refresh();
        }
    }
}
