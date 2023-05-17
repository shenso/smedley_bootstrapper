using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Smedley.Bootstrapper.Models;

namespace Smedley.Bootstrapper.Binders
{
    public class ModCheckboxItemBinder : Binder
    {
        private bool _checked;

        public Mod Mod { get; }
        public string Name { get => Mod.Name;  }
        public bool IsChecked { get { return _checked; } set { SetProperty(ref _checked, value); } }

        public ModCheckboxItemBinder(Mod mod, bool isChecked = false)
        {
            Mod = mod;
            _checked = isChecked;
        }
    }
}
