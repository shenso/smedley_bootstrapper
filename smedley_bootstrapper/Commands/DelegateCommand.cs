using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Windows.Input;

namespace Smedley.Bootstrapper.Commands
{
    public class DelegateCommand : ICommand
    {
        private Action<object?> _action;
        private Predicate<object>? _predicate;

        public event EventHandler? CanExecuteChanged;

        public DelegateCommand(Action<object?> action, Predicate<object>? predicate = null)
        {
            _action = action;
            _predicate = predicate;
        }

        public bool CanExecute(object? parameter)
        {
            if (_predicate != null)
            {
                return _predicate(this);
            } else
            {
                return true;
            }
        }

        public void Execute(object? parameter)
        {
            _action(parameter);
        }
    }
}
