using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Smedley.Bootstrapper.Models;

namespace Smedley.Bootstrapper.Binders
{
    class SettingsBinder : Binder
    {
        private BootstrapSettings _settings;

        public bool ResumeGameThreadAfterLoad
        {
            get
            {
                return _settings.ResumeGameThreadAfterLoad;
            }

            set
            {
                _settings.ResumeGameThreadAfterLoad = value;
                RaisePropertyChanged("ResumeGameThreadAfterLoad");
            }
        }

        public SettingsBinder(BootstrapSettings settings)
        {
            _settings = settings;
        }
    }
}
