using System.Reflection;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Headless;
using Avalonia.Interactivity;
using Avalonia.Input;
using Avalonia.Threading;
using Avalonia.VisualTree;

namespace TKNetUI.VisualChecks;

/// <summary>
/// Renders the production AXAML and code-behind in an isolated in-process headless
/// platform. No scan, authentication, file-manager or network-interface handlers
/// are invoked. All displayed results use reserved documentation addresses.
/// </summary>
internal static partial class PreviewProgram
{
    private static readonly List<object> Measurements = new();
    private static int _assertions;

    [STAThread]
    public static int Main(string[] args)
    {
        string output = Path.GetFullPath(args.FirstOrDefault() ?? "artifacts/ui-preview");
        Directory.CreateDirectory(output);
        AppBuilder.Configure<App>()
            .UseSkia()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
            .WithInterFont()
            .SetupWithoutStarting();

        using var lifetime = new WindowLifetime();
        MainWindow window = lifetime.Window;
        window.Width = 1400;
        window.Height = 900;
        window.Show();
        Assert(Find<TextBox>(window, "SmbPassTextBox").PasswordChar != '\0', "The credential field remains masked.");
        Assert(Find<Button>(window, "ScanAliveBtn").IsEnabled && Find<Button>(window, "ScanSmbBtn").IsEnabled,
            "Both scan actions remain available before a scan.");
        Assert(!Find<Button>(window, "StopBtn").IsEnabled, "Stop remains disabled while no scan is running.");
        if (!OperatingSystem.IsWindows())
            Assert(!Find<CheckBox>(window, "EnableWMICheckBox").IsEnabled, "WMI retains its platform restriction.");
        Capture(window, output, "01-ready-1400x900", 1400, 900);

        Find<TextBox>(window, "ScopeTextBox").Text = "192.168.0.0/16\n10.20.0.0/16\n10.21.40.1/22\n" +
            string.Join("\n", Enumerable.Range(100, 11).Select(n => $"10.22.{n}.0/24"));
        Flush(window);
        Assert(!Find<TextBlock>(window, "ScopeErrorText").IsVisible &&
            Find<TextBlock>(window, "ScopeCountText").Text == $"{134884:N0} hosts",
            "Multiple CIDRs above 65536 addresses load without a false invalid-entry warning.");
        object[] scanSettings = { 0, 0 };
        Assert((bool)typeof(MainWindow).GetMethod("TryReadScanSettings", BindingFlags.Instance | BindingFlags.NonPublic)!
            .Invoke(window, scanSettings)! && (int)scanSettings[0] == 50 && (int)scanSettings[1] == 3,
            "The actual scan validation accepts the large scope and preserves Threads/Timeout.");
        Capture(window, output, "21-large-scope-900x550", 900, 550);

        Populate(window);
        SelectTab(window, "SmbTab");
        Capture(window, output, "02-smb-1400x900", 1400, 900);
        SelectTab(window, "AliveTab");
        Capture(window, output, "03-discovery-1400x900", 1400, 900);

        Find<Button>(window, "SettingsBtn").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Assert(Find<Control>(window, "SettingsDrawer").IsVisible, "Settings opens through the real button handler.");
        Capture(window, output, "04-settings-1400x900", 1400, 900);
        Capture(window, output, "05-settings-1000x650", 1000, 650);
        Capture(window, output, "06-settings-900x550", 900, 550);
        var showAll = Find<CheckBox>(window, "ShowAllDiscoveryCheckBox");
        var settingsScroll = showAll.GetVisualAncestors().OfType<ScrollViewer>().First();
        settingsScroll.ScrollToEnd();
        Flush(window);
        Assert(settingsScroll.Offset.Y > 0, "Settings can scroll to the lower options at minimum size.");
        Capture(window, output, "06b-settings-options-900x550", 900, 550,
            new[] { "SettingsDrawer", "DiscoveryAttempts", "ShowAllDiscoveryCheckBox" });
        showAll.IsChecked = true;
        Flush(window);
        Assert(window.AliveResults.Count == 6, "Show all checked IPs reveals the synthetic address with no response.");
        showAll.IsChecked = false;
        Flush(window);
        Assert(window.AliveResults.Count == 4, "Disabling show all shows only confirmed hosts.");
        window.KeyPressQwerty(PhysicalKey.Escape, RawInputModifiers.None);
        window.KeyReleaseQwerty(PhysicalKey.Escape, RawInputModifiers.None);
        Flush(window);
        Assert(!Find<Control>(window, "SettingsDrawer").IsVisible, "Escape closes the settings drawer.");
        SelectTab(window, "SmbTab");
        Capture(window, output, "07-smb-1000x650", 1000, 650);
        Capture(window, output, "08-smb-900x550", 900, 550);
        Find<Button>(window, "LogToggleBtn").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Assert(Find<Control>(window, "LogContent").IsVisible, "The activity log opens through its real button handler.");
        Capture(window, output, "09-expanded-log-1400x900", 1400, 900);
        Capture(window, output, "10-expanded-log-900x550", 900, 550);
        Find<Button>(window, "LogToggleBtn").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));

        Find<TextBox>(window, "FilterTextBox").Text = "no-such-synthetic-host";
        Flush(window);
        Assert(window.SmbResults.Count == 0, "A nonmatching filter hides all SMB rows.");
        Assert(Find<Control>(window, "EmptyState").IsVisible, "A nonmatching filter displays the empty state.");
        Capture(window, output, "11-filter-empty-1400x900", 1400, 900);
        Capture(window, output, "12-filter-empty-900x550", 900, 550);

        Find<TextBox>(window, "FilterTextBox").Text = "files-01";
        Flush(window);
        Assert(window.SmbResults.Count == 1, "Existing filter matches the synthetic SMB hostname.");
        Assert(window.SmbResults[0].Shares.Length == 4, "Filtering preserves share details and access flags.");
        Find<Button>(window, "ClearFilterBtn").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Flush(window);
        Assert(window.SmbResults.Count == 4, "Clearing the filter restores all synthetic SMB results.");
        Assert(!Find<Control>(window, "ClearFilterBtn").IsVisible, "Clear-filter control hides when the filter is empty.");

        double widthWithScope = Find<Control>(window, "ResultsTabControl").Bounds.Width;
        Find<Button>(window, "ScopeToggleBtn").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Flush(window);
        Assert(!Find<Control>(window, "ScopePanel").IsVisible, "The scope panel collapses through its button handler.");
        Assert(Find<Control>(window, "ResultsTabControl").Bounds.Width > widthWithScope, "Collapsing scope makes more room for results.");
        Capture(window, output, "13-scope-hidden-900x550", 900, 550);
        SelectTab(window, "UnreachableTab");
        Capture(window, output, "14-unreachable-900x550", 900, 550);
        Assert(window.UnreachableResults.Count == 1 && window.UnreachableResults[0].IP == "198.51.100.14",
            "The unreachable tab preserves the synthetic diagnostic result.");

        Find<Button>(window, "ScopeToggleBtn").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        SelectTab(window, "AliveTab");
        // Only change presentation state; never invoke either scan handler.
        Invoke(window, "SetScanningState", true);
        Find<ProgressBar>(window, "ScanProgressBar").Value = 42;
        Find<TextBlock>(window, "StatusTextBlock").Text = "Preview: discovery in progress · synthetic data only";
        Assert(!Find<Button>(window, "ScanAliveBtn").IsEnabled && !Find<Button>(window, "ScanSmbBtn").IsEnabled && Find<Button>(window, "StopBtn").IsEnabled,
            "The scanning presentation disables both start actions and enables Stop.");
        Assert(Find<TextBlock>(window, "ScanStateText").Text == "Scanning", "The scanning presentation updates the status badge.");
        Capture(window, output, "15-scanning-900x550", 900, 550);
        Invoke(window, "SetScanningState", false);
        Find<ProgressBar>(window, "ScanProgressBar").Value = 0;
        Find<TextBlock>(window, "StatusTextBlock").Text = "Preview: inline scope validation · synthetic input only";
        Find<TextBox>(window, "ScopeTextBox").Text = "192.0.2.10\ninvalid-" + new string('x', 400);
        Flush(window);
        Assert(Find<TextBlock>(window, "ScopeErrorText").IsVisible, "Invalid scope input displays its parse error inline.");
        Capture(window, output, "16-invalid-scope-900x550", 900, 550);
        Find<TextBox>(window, "ScopeTextBox").Text = "192.0.2.10";
        Flush(window);
        Assert(!Find<TextBlock>(window, "ScopeErrorText").IsVisible, "Correcting the scope clears its inline error.");

        SelectTab(window, "AliveTab");
        Assert(Find<TabItem>(window, "AliveTab").Header?.ToString() == "Discovery (4/6)",
            "Discovery indicates both visible and checked counts when no-response rows are hidden.");
        foreach (string filter in new[] { "02:00:00:00:00:10", "files-01.example.test", "3389" })
        {
            Find<TextBox>(window, "FilterTextBox").Text = filter;
            Flush(window);
            Assert(window.AliveResults.Count == 1 && window.AliveResults[0].IP == "192.0.2.10",
                "Discovery filtering includes MAC, DNS and observed port metadata.");
        }
        Find<Button>(window, "SettingsBtn").Focus();
        window.KeyPressQwerty(PhysicalKey.F, RawInputModifiers.Control);
        window.KeyReleaseQwerty(PhysicalKey.F, RawInputModifiers.Control);
        Flush(window);
        Assert(Find<TextBox>(window, "FilterTextBox").IsKeyboardFocusWithin, "Ctrl+F focuses the results filter.");
        window.KeyPressQwerty(PhysicalKey.Escape, RawInputModifiers.None);
        window.KeyReleaseQwerty(PhysicalKey.Escape, RawInputModifiers.None);
        Flush(window);
        Assert(string.IsNullOrEmpty(Find<TextBox>(window, "FilterTextBox").Text) && window.AliveResults.Count == 4,
            "Escape clears the focused filter without losing results.");

        var longShareHost = new SmbResult
        {
            IP = "192.0.2.9", Hostname = "long-share-preview", Port445Open = true, Status = "Authenticated",
            Shares = new[] { Share("Team archive " + new string('x', 180), true, false) }
        };
        longShareHost.Normalize();
        GetField<List<SmbResult>>(window, "_allSmb").Add(longShareHost);
        window.SmbResults.Add(longShareHost);
        SelectTab(window, "SmbTab");
        var smbGrid = Find<DataGrid>(window, "SmbDataGrid");
        smbGrid.Columns[0].Sort(System.ComponentModel.ListSortDirection.Ascending);
        Flush(window);
        Assert(smbGrid.CollectionView.Cast<SmbResult>().First().IP == "192.0.2.9", "The production grid sorts .9 before .10.");
        Find<TextBox>(window, "FilterTextBox").Text = "192.0.2";
        Flush(window);
        Assert(smbGrid.CollectionView.Cast<SmbResult>().First().IP == "192.0.2.9", "Bulk filtering preserves the active sort order.");
        Find<TextBox>(window, "FilterTextBox").Text = "";
        Capture(window, output, "17-long-share-1400x900", 1400, 900);
        var chip = smbGrid.GetVisualDescendants().OfType<Border>()
            .First(c => c.Classes.Contains("sharechip") && ReferenceEquals(c.DataContext, longShareHost.Shares[0]));
        Assert(chip.Bounds.Width <= 350 && chip.Focusable, "Long share names stay bounded and can receive keyboard focus.");
        var accessLabel = chip.GetVisualDescendants().OfType<TextBlock>().Single(t => t.Text == "R");
        Assert(WindowBounds(accessLabel, window).Right <= WindowBounds(chip, window).Right,
            "A long share name cannot hide its access indicator.");
        foreach (string name in new[] { "AliveDataGrid", "SmbDataGrid", "UnreachableDataGrid" })
            Assert(Find<DataGrid>(window, name).Columns[0].MinWidth >= 160,
                "IP columns reserve space for a complete IPv4 address.");
        Assert(ToolTip.GetTip(chip)?.ToString()?.Contains(longShareHost.Shares[0].Name) == true,
            "Truncated share text retains its full target in the tooltip.");

        RunLogScrollChecks(window);
        RunScrollChecks(window, output);
        RunSmbCompletenessChecks(output);
        RunExportSnapshotChecks();
        RunDiscoveryTargetChecks(output);

        var client = GetField<EngineClient>(window, "_client");
        Assert(client.ScanId == 0, "The preview never starts or stops an engine scan.");
        File.WriteAllText(Path.Combine(output, "layout-checks.json"), JsonSerializer.Serialize(new
        {
            source = "Production TKNetUI App.axaml/MainWindow.axaml and code-behind; Avalonia.Headless + Skia",
            syntheticData = true,
            scanStarts = client.ScanId,
            assertions = _assertions,
            captures = Measurements
        }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine($"PASS: {_assertions} visual/layout assertions. PNG output: {output}");
        return 0;
    }

    private static void Populate(MainWindow window)
    {
        Find<TextBox>(window, "ScopeTextBox").Text = "192.0.2.0/28\n198.51.100.10-198.51.100.14";
        var discovery = new[]
        {
            new AliveResult { IP = "192.0.2.10", Hostname = "files-01", IsAlive = true, Status = "Confirmed", DetectionMethod = "ICMP, TCP", ICMPLatency = "2.4 ms", TCPOpenPorts = new[] { 445, 3389 }, DNSName = "files-01.example.test", MACAddress = "02:00:00:00:00:10", MACVendor = "Synthetic fixture" },
            new AliveResult { IP = "192.0.2.11", Hostname = "design-nas", IsAlive = true, Status = "Confirmed", DetectionMethod = "TCP", TCPOpenPorts = new[] { 445 }, DNSName = "design-nas.example.test" },
            new AliveResult { IP = "192.0.2.12", Hostname = "workstation-12", IsAlive = true, Status = "Confirmed", DetectionMethod = "ICMP", ICMPLatency = "7.1 ms", TCPOpenPorts = new[] { 445 } },
            new AliveResult { IP = "198.51.100.10", Hostname = "archive-01", IsAlive = true, Status = "Confirmed", DetectionMethod = "TCP", TCPOpenPorts = new[] { 445 }, DNSName = "archive-01.example.test" },
            new AliveResult { IP = "198.51.100.11", Status = "Unconfirmed", ARPObserved = true, Warnings = new[] { "Synthetic fixture: no direct response." } },
            new AliveResult { IP = "198.51.100.14", Status = "No response" }
        };
        var smb = new[]
        {
            new SmbResult { IP = "192.0.2.10", Hostname = "files-01", Port445Open = true, Status = "Authenticated", SMBVersion = "3.1.1", OSVersion = "Windows Server", Shares = new[] { Share("Projects", true, true), Share("Documents", true, false), Share("Finance", false, false), Share("Shared team archive", true, false) } },
            new SmbResult { IP = "192.0.2.11", Hostname = "design-nas", Port445Open = true, Status = "Authenticated", SMBVersion = "3.1.1", OSVersion = "Samba", Shares = new[] { Share("Design", true, true), Share("Assets", true, true), Share("Backups", false, false) } },
            new SmbResult { IP = "192.0.2.12", Hostname = "workstation-12", Port445Open = true, Status = "Authenticated", IsAdmin = true, SMBVersion = "3.0.2", OSVersion = "Windows", Shares = new[] { Share("C$", true, true), Share("ADMIN$", true, true) } },
            new SmbResult { IP = "198.51.100.10", Hostname = "archive-01", Port445Open = true, Status = "Guest Session", SMBVersion = "3.1.1", Shares = new[] { Share("Public", true, false) } }
        };
        foreach (var result in discovery)
        {
            GetField<List<AliveResult>>(window, "_allDiscovery").Add(result);
            if (result.IsAlive) window.AliveResults.Add(result);
        }
        foreach (var result in smb)
        {
            result.Normalize();
            GetField<List<SmbResult>>(window, "_allSmb").Add(result);
            window.SmbResults.Add(result);
        }
        var unreachable = new SmbResult { IP = "198.51.100.14", Status = "Unreachable", Error = "Synthetic fixture: no SMB response" };
        GetField<List<SmbResult>>(window, "_allUnreachable").Add(unreachable);
        window.UnreachableResults.Add(unreachable);
        SetField(window, "_discoveryConfirmed", 4);
        SetField(window, "_smbAdmin", 1);
        SetField(window, "_smbWritable", 3);
        Invoke(window, "UpdateTabHeaders");
        Find<TextBlock>(window, "StatusTextBlock").Text = SmbScanSummary.FormatStatus(smb, 1);
        Find<ProgressBar>(window, "ScanProgressBar").Value = 100;
        Find<TextBox>(window, "LogTextBox").Text = "[14:32:10]  Discovery complete: 4 confirmed hosts.\n[14:32:12]  SMB scan complete: 4 reachable hosts, 1 unreachable.\n[14:32:12]  Preview data only. No network activity was performed.";
    }

    private static ShareInfo Share(string name, bool read, bool write) => new() { Name = name, CanRead = read, CanWrite = write };
    private static void SelectTab(MainWindow window, string name) => Find<TabControl>(window, "ResultsTabControl").SelectedItem = Find<TabItem>(window, name);

    private static void Capture(MainWindow window, string output, string name, int width, int height, string[]? controlsOverride = null)
    {
        window.Width = width;
        window.Height = height;
        Flush(window);
        using var bitmap = window.CaptureRenderedFrame() ?? throw new InvalidOperationException("No rendered frame.");
        Assert(bitmap.PixelSize.Width == width && bitmap.PixelSize.Height == height, $"{name}: exact viewport dimensions.");
        bitmap.Save(Path.Combine(output, name + ".png"));

        var checks = new List<object>();
        bool settings = Find<Control>(window, "SettingsDrawer").IsVisible;
        string[] checkedControls = controlsOverride ?? (settings
            ? new[] { "SettingsDrawer", "SmbDomainTextBox", "SmbUserTextBox", "SmbPassTextBox" }
            : new[] { "ScopeTextBox", "ScopeErrorText", "ThreadsTextBox", "TimeoutTextBox", "ScanAliveBtn", "ScanSmbBtn", "StopBtn", "SettingsBtn", "ScanStateBadge", "FilterTextBox", "ResultsTabControl", "StatusTextBlock", "ScanProgressBar", "LogTextBox" });
        foreach (string controlName in checkedControls)
        {
            var control = Find<Control>(window, controlName);
            if (!control.IsEffectivelyVisible) continue;
            Point point = control.TranslatePoint(default, window) ?? throw new InvalidOperationException($"Cannot locate {controlName}.");
            Rect rect = new(point, control.Bounds.Size);
            Assert(rect.Width > 0 && rect.Height > 0, $"{name}: {controlName} has a usable layout.");
            Assert(rect.Left >= -1 && rect.Top >= -1 && rect.Right <= width + 1 && rect.Bottom <= height + 1, $"{name}: {controlName} remains within the viewport ({rect}).");
            if (controlName == "ScopeTextBox") Assert(rect.Height >= 70, $"{name}: the multiline scope editor remains usable.");
            if (controlName == "LogTextBox") Assert(rect.Height >= 60, $"{name}: the expanded activity log has room for multiple lines.");
            checks.Add(new { control = controlName, x = rect.X, y = rect.Y, width = rect.Width, height = rect.Height });
        }
        object? resultsViewport = null;
        if (!settings && !Find<Control>(window, "EmptyState").IsVisible)
        {
            var grid = Find<TabControl>(window, "ResultsTabControl")
                .GetVisualDescendants().OfType<DataGrid>().Single(g => g.IsEffectivelyVisible);
            var header = grid.GetVisualDescendants().OfType<DataGridColumnHeadersPresenter>().Single();
            var rows = grid.GetVisualDescendants().OfType<DataGridRowsPresenter>().Single();
            Rect gridRect = WindowBounds(grid, window);
            Rect headerRect = WindowBounds(header, window);
            Rect rowsRect = WindowBounds(rows, window);
            Assert(headerRect.Height >= 28 && headerRect.Top >= gridRect.Top - 1 && headerRect.Bottom <= gridRect.Bottom + 1,
                $"{name}: the selected results grid shows its full column header.");
            // Virtualized rows are not necessarily ordered by their screen
            // position. Measure the most visible row, not collection order.
            var visibleRow = rows.GetVisualDescendants().OfType<DataGridRow>()
                .Where(r => r.IsEffectivelyVisible)
                .Select(r => WindowBounds(r, window))
                .Select(r => new { Bounds = r, VisibleHeight = Math.Max(0, Math.Min(r.Bottom, rowsRect.Bottom) - Math.Max(r.Top, rowsRect.Top)) })
                .OrderByDescending(r => r.VisibleHeight).First();
            // Discovery rows can use the theme's compact 38px layout. SMB rows
            // may wrap several shares, so preserve at least a normal 44px row
            // worth of results while the log is expanded at minimum size.
            double normalRowHeight = Math.Min(44, visibleRow.Bounds.Height);
            Assert(normalRowHeight >= 32, $"{name}: populated results retain readable row height.");
            Assert(rowsRect.Height >= normalRowHeight && rowsRect.Top >= headerRect.Bottom - 1 && rowsRect.Bottom <= gridRect.Bottom + 1,
                $"{name}: the selected results viewport has room for at least one normal-height result row ({rowsRect.Height:F1}px).");
            double visibleRowHeight = visibleRow.VisibleHeight;
            Assert(visibleRowHeight >= normalRowHeight,
                $"{name}: at least one normal row's height of populated results remains visible ({visibleRowHeight:F1}px).");
            resultsViewport = new { grid = grid.Name, headerHeight = headerRect.Height, rowsHeight = rowsRect.Height, normalRowHeight, largestVisibleRowHeight = visibleRowHeight };
        }
        Measurements.Add(new { name, width, height, controls = checks, resultsViewport });
    }

    private static Rect WindowBounds(Control control, MainWindow window) => new(
        control.TranslatePoint(default, window) ?? throw new InvalidOperationException($"Cannot locate {control.Name ?? control.GetType().Name}."),
        control.Bounds.Size);

    private static void Flush(MainWindow window)
    {
        for (int i = 0; i < 3; i++)
        {
            Dispatcher.UIThread.RunJobs();
            window.UpdateLayout();
            AvaloniaHeadlessPlatform.ForceRenderTimerTick();
        }
    }

    private static T Find<T>(MainWindow window, string name) where T : Control => window.FindControl<T>(name) ?? throw new InvalidOperationException($"Missing production control: {name}");
    private static T GetField<T>(MainWindow window, string name) => (T)(typeof(MainWindow).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(window) ?? throw new InvalidOperationException($"Missing fixture field: {name}"));
    private static void SetField<T>(MainWindow window, string name, T value) => typeof(MainWindow).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(window, value);
    private static void Invoke(MainWindow window, string name, params object[] arguments) => typeof(MainWindow).GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(window, arguments);
    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("FAIL: " + message);
        _assertions++;
    }

    private sealed class WindowLifetime : IDisposable
    {
        public MainWindow Window { get; } = new();
        public void Dispose() => Window.Close();
    }
}
