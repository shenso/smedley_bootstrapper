using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Smedley.Bootstrapper.Models
{
    public class CoreMod
    {
        public string ID { get;  }

        public string Name { get; set; }

        public string? Description { get; set; }

        public string ModulePath { get; set; }

        public CoreMod(string id, string name, string modulePath, string? description = null)
        {
            ID = id;
            Name = name;
            ModulePath = modulePath;
            Description = description;
        }
    }
}
