using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using Avalonia.VisualTree;

namespace TKNetUI.VisualChecks;

internal static partial class PreviewProgram
{
    private static void RunLogScrollChecks(MainWindow window)
    {
        window.Width = 1400;
        window.Height = 900;
        if (!Find<Control>(window, "LogContent").IsVisible)
            Find<Button>(window, "LogToggleBtn").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Invoke(window, "OnClearLogClick", null!, new RoutedEventArgs());
        Invoke(window, "AppendLog", string.Join('\n', Enumerable.Range(0, 150)
            .Select(i => $"Synthetic scroll line {i:D3} " + new string('x', 240))));
        Flush(window);
        var log = Find<TextBox>(window, "LogTextBox");
        Assert(!log.IsUndoEnabled, "The read-only activity viewer does not retain full-text undo snapshots.");
        var viewer = log.GetVisualDescendants().OfType<ScrollViewer>().Single();
        Assert(viewer.Extent.Height > viewer.Viewport.Height && viewer.Extent.Width > viewer.Viewport.Width,
            "The activity log fixture overflows both axes.");
        log.Focus();
        log.SelectionStart = 50;
        log.SelectionEnd = 70;
        Flush(window);
        viewer.Offset = new Vector(80, 300);
        Flush(window);
        var before = viewer.Offset;
        string selected = log.SelectedText;
        Invoke(window, "AppendLog", "New synthetic line while reading older activity.");
        Flush(window);
        Assert(Math.Abs(viewer.Offset.Y - before.Y) < 1 && Math.Abs(viewer.Offset.X - before.X) < 1,
            "Appending activity preserves both scroll axes while reading older lines.");
        Assert(log.SelectedText == selected, "Appending activity preserves text selected for copying.");
        viewer.ScrollToEnd();
        Flush(window);
        Invoke(window, "AppendLog", "New synthetic line while following the tail.");
        Flush(window);
        Assert(viewer.Extent.Height - viewer.Viewport.Height - viewer.Offset.Y < 1,
            "Activity continues to follow new messages when already at the bottom.");

        Invoke(window, "OnClearLogClick", null!, new RoutedEventArgs());
        Invoke(window, "AppendLog", string.Join('\n', Enumerable.Range(0, BoundedLog.MaxLines)
            .Select(i => $"Retained synthetic line {i:D3} " + new string('x', 180))));
        Flush(window);
        int selection = log.Text!.IndexOf("Retained synthetic line 250", StringComparison.Ordinal);
        log.SelectionStart = selection;
        log.SelectionEnd = selection + "Retained synthetic line 250".Length;
        Flush(window);
        var presenter = log.GetVisualDescendants().OfType<Avalonia.Controls.Presenters.TextPresenter>().Single();
        double lineHeight = presenter.TextLayout.TextLines[0].Height;
        viewer.Offset = new Vector(80, 250 * lineHeight);
        Flush(window);
        before = viewer.Offset;
        selected = log.SelectedText;
        Invoke(window, "AppendLog", "Rotating line 1\nRotating line 2\nRotating line 3");
        Flush(window);
        Assert(log.SelectedText == selected && selected == "Retained synthetic line 250",
            "Rotating the bounded activity buffer preserves a surviving text selection.");
        Assert(Math.Abs(viewer.Offset.Y - (before.Y - 3 * lineHeight)) < 1 && viewer.Offset.X == before.X,
            "Rotating the activity buffer keeps the same retained lines at the same viewport position.");

        Find<Button>(window, "LogToggleBtn").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Invoke(window, "AppendLog", "Arrived while activity was collapsed.");
        Flush(window);
        Find<Button>(window, "LogToggleBtn").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Flush(window);
        Assert(Math.Abs(viewer.Offset.Y - (before.Y - 4 * lineHeight)) < 1,
            "Reopening activity retains the reader's position after messages arrive while collapsed.");
        Invoke(window, "AppendLog", "Batched activity 1");
        Invoke(window, "AppendLog", "Batched activity 2");
        Invoke(window, "AppendLog", "Batched activity 3");
        Flush(window);
        Assert(Math.Abs(viewer.Offset.Y - (before.Y - 7 * lineHeight)) < 1 && log.SelectedText == selected,
            "Several messages before one layout retain the same activity anchor and selection.");
        Invoke(window, "OnClearLogClick", null!, new RoutedEventArgs());
        Flush(window);
        Assert(string.IsNullOrEmpty(log.Text) && viewer.Offset.Y == 0,
            "Clearing activity resets the log and its vertical position.");
        Find<Button>(window, "LogToggleBtn").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));

        var delivered = new List<int>();
        for (int i = 0; i < 250; i++)
        {
            int sequence = i;
            Invoke(window, "PostEngineUpdate", (Action)(() => delivered.Add(sequence)));
        }
        int deliveredBeforeInput = -1;
        Dispatcher.UIThread.Post(() => deliveredBeforeInput = delivered.Count, DispatcherPriority.Input);
        Flush(window);
        Assert(deliveredBeforeInput == 0, "Queued scan presentation yields to pending wheel/input events.");
        Assert(delivered.SequenceEqual(Enumerable.Range(0, 250)),
            "Yielding to input preserves all scan presentation callbacks in their original order.");

        var client = GetField<EngineClient>(window, "_client");
        var scanId = typeof(EngineClient).GetField("_scanId", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;
        bool staleDelivered = false;
        Invoke(window, "PostEngineUpdate", (Action)(() => staleDelivered = true));
        scanId.SetValue(client, 1); // fixture-only generation change; no scan or process is started
        Flush(window);
        scanId.SetValue(client, 0);
        Assert(!staleDelivered, "Background presentation still discards callbacks from an earlier scan generation.");
    }
}
