using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Smedley.Bootstrapper.Models;

namespace Smedley.Bootstrapper.Binders
{
    public class PluginCheckboxItemBinder : Binder
    {
        private bool _checked;

        public Plugin Plugin { get; }
        public string Name { get;  }
        public bool IsChecked { get { return _checked; } set { SetProperty(ref _checked, value); } }

        public PluginCheckboxItemBinder(Plugin plugin, bool isChecked = false)
        {
            Plugin = plugin;
            Name = Path.GetFileName(plugin.ModulePath);
            _checked = isChecked;
        }
    }
}
