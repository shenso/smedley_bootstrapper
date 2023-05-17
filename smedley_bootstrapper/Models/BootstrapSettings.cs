using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Smedley.Bootstrapper.Models
{
    public class BootstrapSettings
    {
        public string GameDirectoryPath { get; set; }
        public string KernelPath { get; set; }

        public List<Plugin> SelectedPlugins { get; }
        public List<Mod> SelectedMods { get; }

        public BootstrapSettings(string gameDir, string kernelPath)
        {
            GameDirectoryPath = gameDir;
            KernelPath = kernelPath;

            SelectedPlugins = new List<Plugin>(); 
            SelectedMods = new List<Mod>(); 
        }

        public string GetCommandLine()
        {
            StringBuilder sb = new();
            sb.Append(GameDirectoryPath);
            sb.Append("\\v2game.exe");

            foreach (Mod mod in SelectedMods)
            {
                var filename = Path.GetFileName(mod.FilePath);
                sb.Append(" -mod=mod/");
                sb.Append(filename);
            }

            return sb.ToString();
        }

        public static string GetDefaultGameDirectory()
        {
            var path = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Victoria 2";
            if (Directory.Exists(path))
            {
                return path;
            }

            return "";
        }
    }
}
