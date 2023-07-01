using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Smedley.Bootstrapper.Models;

namespace Smedley.Bootstrapper.Binders
{
    public class PluginViewBinder : Binder
    {
        public PluginCheckboxListBinder PluginCheckboxListBinder { get; }
        public ModCheckboxListBinder ModCheckboxListBinder { get; }

        public PluginViewBinder(BootstrapSettings settings)
        {
            PluginCheckboxListBinder = new PluginCheckboxListBinder(settings);
            ModCheckboxListBinder = new ModCheckboxListBinder(settings);
        }

        public void Refresh()
        {
            PluginCheckboxListBinder.Refresh();
            ModCheckboxListBinder.Refresh();
        }
    }
}
