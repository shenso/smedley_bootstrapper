using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Smedley.Bootstrapper.Models;

namespace Smedley.Bootstrapper.Binders
{
    public class PluginCheckboxListBinder : Binder
    {
        private BootstrapSettings _settings;
        private ObservableCollection<PluginCheckboxItemBinder> _items;

        public ObservableCollection<PluginCheckboxItemBinder> CheckboxItems { get { return _items; } set { SetProperty(ref _items, value); } }

        public PluginCheckboxListBinder(BootstrapSettings settings)
        {
            _settings = settings;
            _items = new ObservableCollection<PluginCheckboxItemBinder>(SeedItems(settings.GameDirectoryPath + "\\plugins").ToList());
        }

        private IEnumerable<PluginCheckboxItemBinder> SeedItems(string dirname)
        {
            if (Directory.Exists(dirname))
            {
                foreach (string filename in Directory.GetFiles(dirname, "*.dll"))
                {
                    var item = new PluginCheckboxItemBinder(new Plugin(filename));
                    item.PropertyChanged += OnItemPropertyChanged;
                    yield return item;
                }

            }
        }

        private void OnItemPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == "IsChecked" && sender != null)
            {
                var item = (PluginCheckboxItemBinder) sender;
                if (item.IsChecked)
                {
                    _settings.SelectedPlugins.Add(item.Plugin);
                } else
                {
                    _settings.SelectedPlugins.Remove(item.Plugin);
                }
            }
        }
    }
}
