using System.Diagnostics;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Headless;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.VisualTree;

namespace TKNetUI.VisualChecks;

internal static partial class PreviewProgram
{
    // These addresses belong to the benchmarking range. They are display-only
    // fixtures: this harness never invokes a scan or opens a share.
    private static string ScrollFixtureIp(int index) => $"198.18.{index / 256}.{index % 256}";

    internal static void RunScrollChecks(MainWindow window, string output)
    {
        var samples = new List<object>();
        int initialAssertions = _assertions;
        var discovery = Enumerable.Range(0, 10_000).Select(i => new AliveResult
        {
            IP = ScrollFixtureIp(i), Hostname = $"scroll-host-{i:D5}", IsAlive = true,
            Status = "Confirmed", DetectionMethod = "Synthetic fixture", ICMPLatency = "1.0 ms",
            TCPOpenPorts = new[] { 445 }, MACVendor = "Offline scroll fixture"
        }).ToArray();
        var smb = Enumerable.Range(0, 1_500).Select(i =>
        {
            int shareCount = i == 750 ? 48 : new[] { 0, 1, 3, 8, 18 }[i % 5];
            var item = new SmbResult
            {
                IP = ScrollFixtureIp(i), Hostname = $"scroll-files-{i:D4}",
                Port445Open = true, Status = "Authenticated", SMBVersion = "3.1.1",
                Shares = Enumerable.Range(0, shareCount)
                    .Select(n => Share($"Project archive {n:D2}", n % 3 != 0, n % 3 == 1)).ToArray()
            };
            item.Normalize();
            return item;
        }).ToArray();
        var unreachable = Enumerable.Range(0, 1_500).Select(i => new SmbResult
        {
            IP = ScrollFixtureIp(i), Hostname = $"scroll-unreachable-{i:D4}",
            Status = "Unreachable", Error = "Offline display fixture"
        }).ToArray();

        GetField<List<AliveResult>>(window, "_allDiscovery").Clear();
        GetField<List<AliveResult>>(window, "_allDiscovery").AddRange(discovery);
        GetField<List<SmbResult>>(window, "_allSmb").Clear();
        GetField<List<SmbResult>>(window, "_allSmb").AddRange(smb);
        GetField<List<SmbResult>>(window, "_allUnreachable").Clear();
        GetField<List<SmbResult>>(window, "_allUnreachable").AddRange(unreachable);
        window.AliveResults.ReplaceAll(discovery);
        window.SmbResults.ReplaceAll(smb);
        window.UnreachableResults.ReplaceAll(unreachable);
        Invoke(window, "UpdateTabHeaders");

        foreach (var size in new[] { new Size(900, 550), new Size(1400, 900) })
        {
            window.Width = size.Width;
            window.Height = size.Height;
            CheckGridScrolling(window, "AliveTab", "AliveDataGrid", discovery, size, samples);
            CheckGridScrolling(window, "SmbTab", "SmbDataGrid", smb, size, samples);
            CheckGridScrolling(window, "UnreachableTab", "UnreachableDataGrid", unreachable, size, samples);

            SelectTab(window, "SmbTab");
            var grid = Find<DataGrid>(window, "SmbDataGrid");
            grid.ScrollIntoView(smb[750], grid.Columns[3]);
            Flush(window);
            var rows = grid.GetVisualDescendants().OfType<DataGridRowsPresenter>().Single();
            var tallRow = grid.GetVisualDescendants().OfType<DataGridRow>()
                .Single(r => ReferenceEquals(r.DataContext, smb[750]));
            Assert(tallRow.Bounds.Height > rows.Bounds.Height,
                $"{size}: the SMB fixture exercises a row taller than the results viewport.");
            var lastShare = tallRow.GetVisualDescendants().OfType<Border>()
                .Single(c => c.Classes.Contains("sharechip") && ReferenceEquals(c.DataContext, smb[750].Shares[^1]));
            for (int step = 0; step < 160 && !IntersectsViewport(lastShare, rows, window); step++)
            {
                window.MouseWheel(WindowBounds(rows, window).Center, new Vector(0, -1));
                Flush(window);
            }
            Assert(IntersectsViewport(lastShare, rows, window),
                $"{size}: every share in a tall SMB row can be reached with the wheel.");
            Assert(grid.GetVisualDescendants().OfType<DataGridRow>().Count() < 120,
                $"{size}: tall SMB rows do not disable row virtualization.");
        }

        SelectTab(window, "AliveTab");
        var aliveGrid = Find<DataGrid>(window, "AliveDataGrid");
        aliveGrid.ScrollIntoView(discovery[5_000], aliveGrid.Columns[0]);
        Flush(window);
        var vertical = GridScrollBar(aliveGrid, Orientation.Vertical);
        double offsetBeforeAppend = vertical.Value;
        var firstBeforeAppend = VisibleGridItems(aliveGrid, window).First();
        for (int i = 10_000; i < 10_100; i++)
        {
            var item = new AliveResult { IP = ScrollFixtureIp(i), Hostname = $"appended-{i}", IsAlive = true };
            GetField<List<AliveResult>>(window, "_allDiscovery").Add(item);
            window.AliveResults.Add(item);
        }
        Flush(window);
        Assert(vertical.Value > 0 && Math.Abs(vertical.Value - offsetBeforeAppend) < 2,
            "Appending discovery results while scrolled preserves the scroll offset.");
        Assert(VisibleGridItems(aliveGrid, window).Contains(firstBeforeAppend),
            "Appending discovery results keeps the reader's current row visible.");

        window.Width = 900;
        window.Height = 550;
        Flush(window);
        CheckEditorScrolling(window, Find<TextBox>(window, "ScopeTextBox"), "scope", 200);

        Find<Button>(window, "SettingsBtn").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Flush(window);
        var settingsScroll = Find<CheckBox>(window, "ShowAllDiscoveryCheckBox")
            .GetVisualAncestors().OfType<ScrollViewer>().First();
        CheckScrollViewerWheel(window, settingsScroll, "settings");
        settingsScroll.ScrollToEnd();
        Flush(window);
        Assert(settingsScroll.Offset.Y > 0, "Settings lower options remain reachable at minimum window size.");
        settingsScroll.ScrollToHome();
        Flush(window);
        Assert(settingsScroll.Offset.Y < 1, "Settings can return to the top.");
        Find<Button>(window, "SettingsBtn").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));

        File.WriteAllText(Path.Combine(output, "scroll-checks.json"), JsonSerializer.Serialize(new
        {
            syntheticData = true,
            discoveryRows = discovery.Length,
            smbRows = smb.Length,
            largestShareCount = 48,
            assertions = _assertions - initialAssertions,
            timingNote = "Headless render/layout diagnostics only; no wall-clock pass threshold or desktop FPS claim.",
            samples
        }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"PASS: {_assertions - initialAssertions} offline scrolling assertions.");
    }

    private static void CheckGridScrolling<T>(MainWindow window, string tabName, string gridName,
        T[] items, Size size, List<object> samples) where T : class
    {
        SelectTab(window, tabName);
        // Allow the newly selected tab and its viewport to be attached before
        // requesting a particular row. Hidden grids have no current viewport.
        Flush(window);
        var grid = Find<DataGrid>(window, gridName);
        grid.ScrollIntoView(items[0], grid.Columns[0]);
        Flush(window);
        var presenter = grid.GetVisualDescendants().OfType<DataGridRowsPresenter>().Single();
        var vertical = GridScrollBar(grid, Orientation.Vertical);
        Assert(vertical.Maximum > 0, $"{gridName}/{size}: results overflow vertically.");
        Assert(VisibleGridItems(grid, window).Contains(items[0]), $"{gridName}/{size}: first result is reachable.");
        int maximumRealized = 0;
        var timings = new List<double>();
        double initial = vertical.Value;
        for (int step = 0; step < 12; step++)
        {
            var timer = Stopwatch.StartNew();
            window.MouseWheel(WindowBounds(presenter, window).Center, new Vector(0, -3));
            Flush(window);
            timer.Stop();
            timings.Add(timer.Elapsed.TotalMilliseconds);
            maximumRealized = Math.Max(maximumRealized, grid.GetVisualDescendants().OfType<DataGridRow>().Count());
        }
        double afterDown = vertical.Value;
        Assert(afterDown > initial, $"{gridName}/{size}: downward wheel input moves results.");
        window.MouseWheel(WindowBounds(presenter, window).Center, new Vector(0, 3));
        Flush(window);
        Assert(vertical.Value < afterDown, $"{gridName}/{size}: upward wheel input moves results.");
        Assert(maximumRealized > 0 && maximumRealized < 120,
            $"{gridName}/{size}: only a bounded viewport of {items.Length:N0} rows is realized ({maximumRealized}).");

        var horizontal = GridScrollBar(grid, Orientation.Horizontal);
        if (gridName != "UnreachableDataGrid")
        {
            Assert(horizontal.Maximum > 0, $"{gridName}/{size}: wide result columns overflow horizontally.");
            double beforeRight = horizontal.Value;
            window.MouseWheel(WindowBounds(presenter, window).Center, new Vector(-3, 0));
            Flush(window);
            double afterRight = horizontal.Value;
            Assert(afterRight > beforeRight, $"{gridName}/{size}: horizontal wheel input reaches right-hand columns.");
            window.MouseWheel(WindowBounds(presenter, window).Center, new Vector(3, 0));
            Flush(window);
            Assert(horizontal.Value < afterRight, $"{gridName}/{size}: horizontal wheel input returns left.");
        }

        grid.ScrollIntoView(items[^1], grid.Columns[0]);
        Flush(window);
        Assert(VisibleGridItems(grid, window).Contains(items[^1]), $"{gridName}/{size}: the final result is reachable.");
        grid.ScrollIntoView(items[0], grid.Columns[0]);
        Flush(window);
        Assert(VisibleGridItems(grid, window).Contains(items[0]), $"{gridName}/{size}: returning to the first result works.");
        samples.Add(new
        {
            grid = gridName, width = size.Width, height = size.Height, items = items.Length,
            wheelSteps = timings.Count, maximumRealizedRows = maximumRealized,
            medianStepMilliseconds = timings.OrderBy(t => t).ElementAt(timings.Count / 2),
            maximumStepMilliseconds = timings.Max()
        });
    }

    private static void CheckEditorScrolling(MainWindow window, TextBox editor, string label, int lines)
    {
        string? original = editor.Text;
        editor.Text = string.Join('\n', Enumerable.Range(0, lines).Select(i => $"# Offline scroll fixture {i:D4} " + new string('x', 150)));
        editor.CaretIndex = 0;
        Flush(window);
        var scroll = editor.GetVisualDescendants().OfType<ScrollViewer>().First();
        scroll.Offset = default;
        Flush(window);
        CheckScrollViewerWheel(window, scroll, label);
        double xBefore = scroll.Offset.X;
        window.MouseWheel(WindowBounds(scroll, window).Center, new Vector(-3, 0));
        Flush(window);
        Assert(scroll.Offset.X > xBefore, $"The {label} editor scrolls horizontally for long lines.");
        window.MouseWheel(WindowBounds(scroll, window).Center, new Vector(3, 0));
        Flush(window);
        Assert(scroll.Offset.X <= xBefore + 1, $"The {label} editor can return to the left edge.");
        editor.Text = original;
        editor.CaretIndex = 0;
        Flush(window);
    }

    private static void CheckScrollViewerWheel(MainWindow window, ScrollViewer scroll, string label)
    {
        scroll.ScrollToHome();
        Flush(window);
        Point point = WindowBounds(scroll, window).Center;
        double beforeDown = scroll.Offset.Y;
        window.MouseWheel(point, new Vector(0, -3));
        Flush(window);
        double afterDown = scroll.Offset.Y;
        Assert(afterDown > beforeDown, $"The {label} responds to downward wheel input.");
        window.MouseWheel(point, new Vector(0, 3));
        Flush(window);
        Assert(scroll.Offset.Y < afterDown, $"The {label} responds to upward wheel input.");
    }

    private static ScrollBar GridScrollBar(DataGrid grid, Orientation orientation) =>
        grid.GetVisualDescendants().OfType<ScrollBar>().Single(s => s.Orientation == orientation);

    private static object[] VisibleGridItems(DataGrid grid, MainWindow window)
    {
        var presenter = grid.GetVisualDescendants().OfType<DataGridRowsPresenter>().Single();
        return presenter.GetVisualDescendants().OfType<DataGridRow>()
            .Where(r => r.DataContext is not null && IntersectsViewport(r, presenter, window))
            .OrderBy(r => WindowBounds(r, window).Top).Select(r => r.DataContext!).ToArray();
    }

    private static bool IntersectsViewport(Control child, Control viewport, MainWindow window)
    {
        if (!child.IsEffectivelyVisible) return false;
        Rect item = WindowBounds(child, window);
        Rect area = WindowBounds(viewport, window);
        return item.Bottom > area.Top + 1 && item.Top < area.Bottom - 1 &&
            item.Right > area.Left + 1 && item.Left < area.Right - 1;
    }
}
