using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Smedley.Bootstrapper.Models
{
    public class Plugin
    {
        public string ModulePath { get; set; }

        public Plugin(string modulePath)
        {
            ModulePath = modulePath;
        }
    }
}
