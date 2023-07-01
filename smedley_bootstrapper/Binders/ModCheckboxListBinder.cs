using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Smedley.Bootstrapper.Models;

namespace Smedley.Bootstrapper.Binders
{
    public class ModCheckboxListBinder : Binder
    {

        private BootstrapSettings _settings;
        private ObservableCollection<object> _items;

        public ObservableCollection<object> CheckboxItems { get { return _items; } set { SetProperty(ref _items, value); } }

        public ModCheckboxListBinder(BootstrapSettings settings)
        {
            _settings = settings;
            _items = new ObservableCollection<object>(SeedItems(settings.GameDirectoryPath + "\\mod").ToList());
        }

        private IEnumerable<object> SeedItems(string dirname)
        {
            if (Directory.Exists(dirname))
            {
                foreach (string filename in Directory.GetFiles(dirname, "*.mod"))
                {
                    var item = new ModCheckboxItemBinder(ReadModFile(filename));
                    item.PropertyChanged += OnItemPropertyChanged;
                    yield return item;
                }
            }
        }

        public void Refresh()
        {
            foreach (var item in CheckboxItems)
            {
                ((ModCheckboxItemBinder) item).PropertyChanged -= OnItemPropertyChanged;
            }
            CheckboxItems = new ObservableCollection<object>(SeedItems(_settings.GameDirectoryPath + "\\mod").ToList());
        }

        private void OnItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == "IsChecked" && sender != null)
            {
                var item = (ModCheckboxItemBinder) sender;
                if (item.IsChecked)
                {
                    _settings.SelectedMods.Add(item.Mod);
                } else
                {
                    _settings.SelectedMods.Remove(item.Mod);
                }
            }
        }

        private Tuple<string, string>? ReadLine(string line)
        {
            int state = 0;
            string key = "";
            string val = "";

            for (int pos = 0; pos < line.Length; pos++) {
                char ch = line[pos];

                switch (state)
                {
                    case 0:
                        if (ch == '=')
                            state = 1;
                        else if (ch != ' ')
                            key += ch;
                        break;
                    case 1:
                        if (ch == ' ')
                            continue;
                        if (ch != '"')
                            return null;
                        state = 2;
                        break;
                    case 2:
                        if (ch == '"')
                            return new Tuple<string, string>(key, val);
                        else if (ch == '\\' && pos != line.Length - 1 && line[pos + 1] == '"')
                        {
                            val += '"';
                            pos++;
                            continue;
                        }
                        else
                            val += ch;
                        break;
                }
            }

            return null;
        }

        private Mod ReadModFile(string path)
        {
            string name = "";

            foreach (var line in File.ReadLines(path).Select(ReadLine).Where(x => x != null))
            {
                if (line.Item1 == "name")
                    name = line.Item2;
            }

            if (name == "")
                name = Path.GetFileNameWithoutExtension(path);

            return new Mod(name, path);
        }
    }
}
