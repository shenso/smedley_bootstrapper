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
        public Binder PluginCheckboxListBinder { get; }

        public PluginViewBinder(BootstrapSettings settings)
        {
            PluginCheckboxListBinder = new PluginCheckboxListBinder(settings);
        }
    }
}
