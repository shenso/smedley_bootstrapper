using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Smedley.Bootstrapper.Models
{
    public class Mod
    {
        public string Name { get; set; }
        public string FilePath { get; }

        public Mod(string name, string filePath)
        {
            Name = name;
            FilePath = filePath;
        }
    }
}
