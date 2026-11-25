using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;

namespace TKNetUI;

// Filtering a large result set should invalidate the grid once, not once per row.
// Individual scan results still use the normal incremental Add notifications.
public sealed class ResultCollection<T> : ObservableCollection<T>
{
    public void ReplaceAll(IEnumerable<T> source)
    {
        // Materialize first so self-filtering and failed enumeration preserve data.
        T[] replacement = source.ToArray();
        CheckReentrancy();
        Items.Clear();
        foreach (T item in replacement) Items.Add(item);
        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }
}
