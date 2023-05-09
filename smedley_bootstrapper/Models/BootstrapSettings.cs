﻿using System;
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

        public List<CoreMod> CoreMods { get; }

        public BootstrapSettings(string gameDir, string kernelPath)
        {
            GameDirectoryPath = gameDir;
            KernelPath = kernelPath;

            CoreMods = new List<CoreMod>(); 
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