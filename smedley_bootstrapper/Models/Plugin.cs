using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using Tomlyn;

namespace Smedley.Bootstrapper.Models
{
    public class Plugin
    {
        [IgnoreDataMember]
        public string DefinitionPath { get; set; }
        [DataMember(Name = "module")]
        public string ModuleName { get; set; }

        [DataMember(Name = "id")]
        public string ID { get; set; }
        [DataMember(Name = "name")]
        public string Name { get; set; }
        [DataMember(Name = "description")]
        public string? Description { get; set; }
        [DataMember(Name = "version")]
        public string Version { get; set; }

        public static Plugin ReadDefinition(string path)
        {
            var model = Toml.ToModel<Plugin>(File.ReadAllText(path));
            model.DefinitionPath = path;
            return model;
        }
    }
}
