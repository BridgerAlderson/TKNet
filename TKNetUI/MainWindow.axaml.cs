using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace TKNetUI;

public partial class MainWindow : Window
{
    // ── Backing stores (all results, unfiltered) ──────────────────────────────
    private readonly List<AliveResult> _allDiscovery = new();
    private readonly List<SmbResult> _allSmb = new();
    private readonly List<SmbResult> _allUnreachable = new(); // SMB scan: port 445 closed

    // ── Filtered views bound to the DataGrids ────────────────────────────────
    public ResultCollection<AliveResult> AliveResults { get; } = new();
    public ResultCollection<SmbResult> SmbResults { get; } = new();
    public ResultCollection<SmbResult> UnreachableResults { get; } = new();

    private readonly EngineClient _client;
    private readonly BoundedLog _log = new();
    private Avalonia.Vector? _pendingLogOffset;
    private bool _followLogTail;
    private int _pendingLogRemovedLines;
    private readonly DolphinSmbLauncher _dolphin = new();
    private readonly System.Threading.CancellationTokenSource _windowLifetime = new();
    private int _smbAdmin, _smbWritable;
    private bool _isScanning;

    // Which scan produced the current results (drives the completion summary).
    private bool _lastScanWasAlive = true;
    private bool _discoveryComplete;
    private DateTimeOffset? _discoveryStartedAt;
    private object? _discoveryConfig;
    private int _discoveryConfirmed;
    private bool _smbComplete;
    private DateTimeOffset? _smbStartedAt;
    private SmbReportSettings? _smbSettings;

    // Row item under the last right-click, resolved for the grid context menus.
    private object? _ctxItem;

    // ── Row highlight brushes ─────────────────────────────────────────────────
    private static readonly ISolidColorBrush AdminRowBrush = new SolidColorBrush(Color.Parse("#251D26")); // admin access
    private static readonly ISolidColorBrush WeakAuthBrush = new SolidColorBrush(Color.Parse("#252219")); // null/guest or unconfirmed
    private static readonly ISolidColorBrush NeutralRowBrush = new SolidColorBrush(Color.Parse("#151B25"));

    public MainWindow()
    {
        InitializeComponent();
        ToolTip.SetTip(StatusTextBlock, StatusTextBlock.Text);
        StatusTextBlock.PropertyChanged += (_, change) =>
        {
            // New activity replaces the previous scan's detailed tooltip.
            if (change.Property == TextBlock.TextProperty)
                ToolTip.SetTip(StatusTextBlock, StatusTextBlock.Text);
        };
        LogTextBox.LayoutUpdated += RestoreLogViewport;
        ScopeTextBox.MaxLength = ExportSupport.MaxScopeCharacters;
        EnableWMICheckBox.IsEnabled = OperatingSystem.IsWindows();
        if (!OperatingSystem.IsWindows()) ToolTip.SetTip(EnableWMICheckBox, "WMI metadata is supported by the Windows build.");

        AliveDataGrid.ItemsSource = AliveResults;
        SmbDataGrid.ItemsSource = SmbResults;
        UnreachableDataGrid.ItemsSource = UnreachableResults;

        _client = new EngineClient();

        _client.OnLog += msg => PostEngineUpdate(() =>
        {
            StatusTextBlock.Text = msg;
            AppendLog(msg);
        });

        _client.OnProgress += prog => PostEngineUpdate(() =>
            ScanProgressBar.Value = prog * 100);

        _client.OnAliveResult += res => PostEngineUpdate(() =>
        {
            _allDiscovery.Add(res);
            if (res.IsAlive) _discoveryConfirmed++;
            if (MatchesFilter(res))
                AliveResults.Add(res);
            UpdateTabHeaders();
        });

        _client.OnSmbResult += res => PostEngineUpdate(() =>
        {
            // Stamp each share with its host IP so a chip can build its own smb:// URL.
            foreach (var sh in res.Shares) sh.IP = res.IP;

            // Keep the main SMB view clean: port-445-open hosts are the interesting
            // ones; everything unreachable (closed/no response) goes to its own tab.
            if (res.Port445Open)
            {
                _allSmb.Add(res);
                if (res.IsAdmin) _smbAdmin++;
                if (res.Shares.Any(s => s.CanWrite)) _smbWritable++;
                if (MatchesFilter(res)) SmbResults.Add(res);
            }
            else
            {
                _allUnreachable.Add(res);
                if (MatchesFilter(res)) UnreachableResults.Add(res);
            }
            if (SmbScanSummary.HostDiagnostic(res) is { } diagnostic) AppendLog(diagnostic);
            UpdateTabHeaders();
        });

        _client.OnDone += () => PostEngineUpdate(() =>
        {
            if (_lastScanWasAlive) _discoveryComplete = true;
            else _smbComplete = true;
            ScanProgressBar.Value = 100;
            SetScanningState(false);
            string summary = _lastScanWasAlive
                ? $"Discovery: {_allDiscovery.Count} checked, {_discoveryConfirmed} confirmed, {_allDiscovery.Count(r => !r.IsAlive && r.HasObservation)} unconfirmed, {_allDiscovery.Count(r => r.HasProbeErrors)} with probe errors."
                : SmbScanSummary.Format(_allSmb, _allUnreachable.Count);
            StatusTextBlock.Text = _lastScanWasAlive ? summary
                : SmbScanSummary.FormatStatus(_allSmb, _allUnreachable.Count, _smbSettings?.PortScanOnly == true);
            ToolTip.SetTip(StatusTextBlock, summary);
            AppendLog($"--- {summary} ---");
            UpdateTabHeaders();
        });

        _client.OnFailed += message => PostEngineUpdate(() =>
        {
            SetScanningState(false);
            StatusTextBlock.Text = message;
            AppendLog("ERROR: " + message);
        });
        Closed += (_, _) => { _windowLifetime.Cancel(); _client.Stop(); };

        // Filter box: re-apply on every keystroke
        FilterTextBox.TextChanged += (_, _) => ApplyFilter();

        // Scope box: recompute the live host count on every keystroke
        ScopeTextBox.TextChanged += (_, _) => UpdateScopeCount();
        UpdateScopeCount();

        // Drive the tab headers from code from the start (single source of truth).
        ScopeToggleBtn.Classes.Set("active", ScopePanel.IsVisible);
        SetScanningState(false);
        UpdateTabHeaders();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void PostEngineUpdate(Action update)
    {
        int scanId = _client.ScanId;
        // A burst of scan results must yield to wheel, keyboard and render work.
        // Keep incremental updates and their FIFO order, including completion.
        Dispatcher.UIThread.Post(() => { if (scanId == _client.ScanId) update(); }, DispatcherPriority.Background);
    }

    private void AppendLog(string msg)
    {
        var viewer = LogTextBox.GetVisualDescendants().OfType<ScrollViewer>().FirstOrDefault();
        if (_pendingLogOffset == null)
        {
            _pendingLogOffset = viewer?.Offset ?? default(Avalonia.Vector);
            _followLogTail = viewer == null || viewer.Extent.Height - viewer.Viewport.Height - viewer.Offset.Y <= 1;
        }
        int caret = LogTextBox.CaretIndex;
        int start = LogTextBox.SelectionStart;
        int end = LogTextBox.SelectionEnd;
        LogTextBox.Text = _log.Append($"[{DateTime.Now:HH:mm:ss}]  {msg}");
        _pendingLogRemovedLines += _log.RemovedLines;
        // The bounded buffer can discard old lines. Keep surviving selected text
        // attached to the same message rather than silently selecting another one.
        if (_log.RemovedCharacters > 0)
        {
            LogTextBox.CaretIndex = Math.Max(0, caret - _log.RemovedCharacters);
            LogTextBox.SelectionStart = Math.Max(0, start - _log.RemovedCharacters);
            LogTextBox.SelectionEnd = Math.Max(0, end - _log.RemovedCharacters);
        }
    }

    private void RestoreLogViewport(object? sender, EventArgs e)
    {
        if (_pendingLogOffset is not { } offset || !LogTextBox.IsEffectivelyVisible) return;
        var viewer = LogTextBox.GetVisualDescendants().OfType<ScrollViewer>().FirstOrDefault();
        var presenter = LogTextBox.GetVisualDescendants().OfType<Avalonia.Controls.Presenters.TextPresenter>().FirstOrDefault();
        if (viewer == null || presenter == null) return;
        // Use the updated text extent, once per layout, without forcing a layout
        // for every log message or moving the user's caret/selection to the end.
        double lineHeight = presenter.TextLayout.TextLines.FirstOrDefault()?.Height ?? 0;
        double y = _followLogTail ? viewer.Extent.Height - viewer.Viewport.Height
            : offset.Y - _pendingLogRemovedLines * lineHeight;
        _pendingLogOffset = null;
        _pendingLogRemovedLines = 0;
        viewer.Offset = new Avalonia.Vector(offset.X, Math.Max(0, y));
    }

    private void SetScanningState(bool scanning)
    {
        _isScanning = scanning;
        ScanAliveBtn.IsEnabled = !scanning;
        ScanSmbBtn.IsEnabled = !scanning;
        StopBtn.IsEnabled = scanning;
        ScanStateText.Text = scanning ? "Scanning" : "Ready";
        ScanStateBadge.Classes.Set("running", scanning);
        UpdateEmptyState();
    }

    private bool TryReadScanSettings(out int threads, out int timeout)
    {
        threads = timeout = 0;
        var scope = ScopeParser.Analyze(ScopeTextBox.Text);
        if (scope.InvalidLines > 0 || scope.Hosts == 0)
        {
            StatusTextBlock.Text = "Invalid scope: " + (scope.FirstError ?? "no IPv4 hosts");
            return false;
        }
        if (!int.TryParse(ThreadsTextBox.Text, out threads) || threads < 1 || threads > 256 ||
            !int.TryParse(TimeoutTextBox.Text, out timeout) || timeout < 1 || timeout > 60)
        {
            StatusTextBlock.Text = "Use 1–256 threads and a timeout of 1–60 seconds.";
            return false;
        }
        return true;
    }

    // ── Tab headers with result count ─────────────────────────────────────────

    private void UpdateTabHeaders()
    {
        if (FilterTextBox == null || AliveTab == null || SmbTab == null || UnreachableTab == null) return;
        if (ExportAliveTxtMenu != null && ExportAliveJsonMenu != null)
            ExportAliveTxtMenu.IsEnabled = ExportAliveJsonMenu.IsEnabled = _discoveryComplete;
        string filter = FilterTextBox.Text?.Trim() ?? "";
        bool filtering = !string.IsNullOrEmpty(filter);

        if (filtering)
        {
            AliveTab.Header = $"Discovery ({AliveResults.Count}/{_allDiscovery.Count})";
            SmbTab.Header = $"SMB shares ({SmbResults.Count}/{_allSmb.Count})";
            UnreachableTab.Header = $"Unreachable ({UnreachableResults.Count}/{_allUnreachable.Count})";
            int visibleCount = ResultsTabControl.SelectedIndex switch
            {
                1 => SmbResults.Count,
                2 => UnreachableResults.Count,
                _ => AliveResults.Count
            };
            FilterHintText.Text = $"{visibleCount} shown in this view";
        }
        else
        {
            AliveTab.Header = _allDiscovery.Count == 0 ? "Discovery"
                : AliveResults.Count < _allDiscovery.Count ? $"Discovery ({AliveResults.Count}/{_allDiscovery.Count})"
                : $"Discovery ({_allDiscovery.Count})";
            SmbTab.Header = _allSmb.Count > 0 ? $"SMB shares ({_allSmb.Count})" : "SMB shares";
            UnreachableTab.Header = _allUnreachable.Count > 0 ? $"Unreachable ({_allUnreachable.Count})" : "Unreachable";
            FilterHintText.Text = ResultsTabControl.SelectedIndex == 0 && AliveResults.Count < _allDiscovery.Count
                ? $"{AliveResults.Count} shown / {_allDiscovery.Count} checked" : "";
        }

        if (ClearFilterBtn != null) ClearFilterBtn.IsVisible = filtering;
        UpdateStats();
        UpdateEmptyState();
    }

    private void UpdateEmptyState()
    {
        if (ResultsTabControl == null || EmptyState == null || EmptyTitleText == null ||
            EmptyDescriptionText == null || ResultHelpText == null) return;

        int tab = ResultsTabControl.SelectedIndex;
        int visibleCount = tab switch
        {
            1 => SmbResults.Count,
            2 => UnreachableResults.Count,
            _ => AliveResults.Count
        };
        int totalCount = tab switch
        {
            1 => _allSmb.Count,
            2 => _allUnreachable.Count,
            _ => _allDiscovery.Count
        };
        ResultHelpText.Text = tab switch
        {
            1 => "Double-click to open · R: read · W: write · RW: both · ✕: no confirmed access · ?: incomplete check.",
            2 => "Port 445 did not respond or was closed. This does not prove that the host is offline.",
            _ => ShowAllDiscoveryCheckBox.IsChecked == true
                ? "All checked addresses. No response does not prove that a host is offline."
                : "Confirmed hosts only · Export alive IPs as TXT or JSON after discovery finishes."
        };

        EmptyState.IsVisible = visibleCount == 0;
        if (visibleCount > 0) return;

        bool filtering = !string.IsNullOrWhiteSpace(FilterTextBox.Text);
        bool scanningThisView = _isScanning && (tab == 0 ? _lastScanWasAlive : !_lastScanWasAlive);
        if (totalCount > 0)
        {
            EmptyTitleText.Text = filtering ? "No matching results" : "No visible results";
            EmptyDescriptionText.Text = tab == 0
                ? "Clear the filter or include hosts with no response to see more checked addresses."
                : "Clear or adjust the filter to see the results in this view.";
        }
        else if (scanningThisView)
        {
            EmptyTitleText.Text = "Waiting for results";
            EmptyDescriptionText.Text = "The scan is running. Results will appear here as hosts are checked.";
        }
        else
        {
            EmptyTitleText.Text = tab switch
            {
                1 => "No SMB results",
                2 => "No unreachable results",
                _ => "No discovery results"
            };
            EmptyDescriptionText.Text = tab switch
            {
                1 => "Set your scope and credentials, then run an SMB scan to inspect shares and access.",
                2 => "Hosts with a closed or unresponsive SMB port appear here after an SMB scan.",
                _ => "Add IP addresses, ranges or CIDR networks to the scope, then start discovery."
            };
        }
    }

    // Compact live dashboard at the right edge of the filter bar.
    private void UpdateStats()
    {
        if (StatsText == null) return;

        if (_allDiscovery.Count == 0 && _allSmb.Count == 0 && _allUnreachable.Count == 0)
        {
            StatsText.Text = "";
            return;
        }

        int admin = _smbAdmin;
        int writable = _smbWritable;

        var parts = new List<string>();
        if (_allDiscovery.Count > 0) parts.Add($"{_discoveryConfirmed} confirmed / {_allDiscovery.Count} checked");
        if (_allSmb.Count > 0) parts.Add($"{_allSmb.Count} SMB");
        if (admin > 0) parts.Add($"{admin} admin-share access");
        if (writable > 0) parts.Add($"{writable} writable");
        if (_allUnreachable.Count > 0) parts.Add($"{_allUnreachable.Count} unreachable");

        StatsText.Text = string.Join("   ·   ", parts);
    }

    // ── Filter ────────────────────────────────────────────────────────────────

    private bool MatchesFilter(AliveResult r)
    {
        if (ShowAllDiscoveryCheckBox.IsChecked != true && !r.IsAlive) return false;
        string f = FilterTextBox.Text?.Trim() ?? "";
        if (string.IsNullOrEmpty(f)) return true;
        return r.IP.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.Hostname.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.MACVendor.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.MACAddress.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.DNSName.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.NetBIOSName.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.OpenPortsList.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.Status.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.DetectionMethod.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.Diagnostics.Contains(f, StringComparison.OrdinalIgnoreCase);
    }

    private bool MatchesFilter(SmbResult r)
    {
        string f = FilterTextBox.Text?.Trim() ?? "";
        if (string.IsNullOrEmpty(f)) return true;
        return r.IP.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.Hostname.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.OSVersion.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.Status.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.SessionLabel.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.ShareDetails.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.Diagnostics.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.WMIInfo.Contains(f, StringComparison.OrdinalIgnoreCase)
            || r.SNMPInfo.Contains(f, StringComparison.OrdinalIgnoreCase);
    }

    private void ApplyFilter()
    {
        AliveResults.ReplaceAll(_allDiscovery.Where(MatchesFilter));
        SmbResults.ReplaceAll(_allSmb.Where(MatchesFilter));
        UnreachableResults.ReplaceAll(_allUnreachable.Where(MatchesFilter));

        UpdateTabHeaders();
    }

    private void OnClearFilterClick(object? sender, RoutedEventArgs e)
    {
        FilterTextBox.Text = "";
        FilterTextBox.Focus();
    }

    // ── Row coloring (LoadingRow events) ─────────────────────────────────────

    private void AliveDataGrid_LoadingRow(object? sender, DataGridRowEventArgs e)
    {
        // Keep unconfirmed observations visibly separate, including recycled rows.
        e.Row.Background = e.Row.DataContext is AliveResult { IsAlive: false }
            ? WeakAuthBrush : NeutralRowBrush;
    }

    private void SmbDataGrid_LoadingRow(object? sender, DataGridRowEventArgs e)
    {
        if (e.Row.DataContext is not SmbResult r)
            return;

        e.Row.Background = r.IsAdmin
            ? AdminRowBrush                                                  // admin access
            : (r.Status is "Null Session" or "Guest Session")
                ? WeakAuthBrush                                              // unauthenticated / guest
                : NeutralRowBrush;
    }

    // ── Tab changed ───────────────────────────────────────────────────────────

    private void OnTabChanged(object? sender, SelectionChangedEventArgs e)
    {
        // Filter hint text already recalculated on any filter change;
        // recalculate now in case we just switched tabs with an active filter.
        UpdateTabHeaders();
    }

    // ── Settings drawer toggle ────────────────────────────────────────────────

    private void OnSettingsClick(object? sender, RoutedEventArgs e)
    {
        SetSettingsVisible(!SettingsDrawer.IsVisible);
    }

    private void OnSettingsCloseClick(object? sender, RoutedEventArgs e)
    {
        SetSettingsVisible(false);
    }

    private void OnWorkspaceSizeChanged(object? sender, SizeChangedEventArgs e)
    {
        Classes.Set("compact", e.NewSize.Height < 700);
    }

    private void OnWindowKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape && SettingsDrawer.IsVisible)
        {
            SetSettingsVisible(false);
            e.Handled = true;
        }
        else if (!SettingsDrawer.IsVisible && e.Key == Key.F && e.KeyModifiers == KeyModifiers.Control)
        {
            FilterTextBox.Focus();
            FilterTextBox.SelectAll();
            e.Handled = true;
        }
        else if (!SettingsDrawer.IsVisible && e.Key == Key.Escape && FilterTextBox.IsKeyboardFocusWithin)
        {
            FilterTextBox.Text = "";
            e.Handled = true;
        }
    }

    private void SetSettingsVisible(bool visible)
    {
        SettingsDrawer.IsVisible = visible;
        SettingsBtn.Content = "Settings";
        SettingsBtn.Classes.Set("active", visible);
        if (visible)
            SmbDomainTextBox.Focus();
        else
            SettingsBtn.Focus();
    }

    // ── Scope panel ─────────────────────────────────────────────────────────

    private void OnScopeToggleClick(object? sender, RoutedEventArgs e)
    {
        ScopePanel.IsVisible = !ScopePanel.IsVisible;
        ScopeToggleBtn.Content = "Scope";
        ScopeToggleBtn.Classes.Set("active", ScopePanel.IsVisible);
    }

    // Recompute the live "N hosts" badge and surface the first parse problem, if any.
    private void UpdateScopeCount()
    {
        if (ScopeCountText == null) return;

        var s = ScopeParser.Analyze(ScopeTextBox.Text);

        ScopeCountText.Text = s.Hosts switch
        {
            0 => "0 hosts",
            1 => "1 host",
            _ => $"{s.Hosts:N0} hosts"
        };

        if (ScopeErrorText == null) return;

        if (s.InvalidLines > 0 && s.FirstError != null)
        {
            ScopeErrorText.Text = s.InvalidLines == 1
                ? $"⚠ Invalid entry: {s.FirstError}"
                : $"⚠ {s.InvalidLines} invalid entries. First: {s.FirstError}";
            ScopeErrorText.IsVisible = true;
        }
        else
        {
            ScopeErrorText.Text = "";
            ScopeErrorText.IsVisible = false;
        }
    }

    private async void OnScopeLoadClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Load Scope List",
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                new FilePickerFileType("Scope / Text Files") { Patterns = new[] { "*.txt", "*.scope", "*.lst", "*.csv" } },
                new FilePickerFileType("All Files")          { Patterns = new[] { "*" } }
            }
            });

            var file = files?.FirstOrDefault();
            if (file == null) return;

            await using var stream = await file.OpenReadAsync();
            ScopeTextBox.Text = await ExportSupport.ReadScopeAsync(stream);
            UpdateScopeCount();
            StatusTextBlock.Text = $"Scope loaded: {file.Name}";
            AppendLog($"Scope loaded from {file.Name}");
        }
        catch (Exception ex) { StatusTextBlock.Text = "Operation failed: " + ex.Message; }
    }

    private async void OnScopeSaveClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            string scope = ScopeTextBox.Text ?? "";
            var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Save Scope List",
                DefaultExtension = "txt",
                SuggestedFileName = "scope.txt",
                FileTypeChoices = new[]
                {
                new FilePickerFileType("Text Files") { Patterns = new[] { "*.txt" } }
            }
            });

            if (file == null) return;

            await using var stream = await file.OpenWriteAsync();
            await ExportSupport.WriteTextAsync(stream, scope);
            StatusTextBlock.Text = $"Scope saved: {file.Name}";
            AppendLog($"Scope saved to {file.Name}");
        }
        catch (Exception ex) { StatusTextBlock.Text = "Operation failed: " + ex.Message; }
    }

    private void OnScopeClearClick(object? sender, RoutedEventArgs e)
    {
        ScopeTextBox.Text = "";
        UpdateScopeCount();
        ScopeTextBox.Focus();
    }

    // Fill the scope with the CIDR of the first active local IPv4 interface — a
    // one-click "scan my network" convenience à la SoftPerfect Network Scanner.
    private void OnScopeDetectLocalClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            var cidr = DetectLocalCidr();
            if (cidr == null)
            {
                StatusTextBlock.Text = "Could not detect a local IPv4 subnet.";
                return;
            }

            string existing = ScopeTextBox.Text ?? "";
            if (existing.Split('\n').Any(l => l.Trim() == cidr))
            {
                StatusTextBlock.Text = $"{cidr} is already in the scope.";
                return;
            }

            ScopeTextBox.Text = string.IsNullOrWhiteSpace(existing)
                ? cidr
                : existing.TrimEnd('\n') + "\n" + cidr;
            UpdateScopeCount();
            StatusTextBlock.Text = $"Added local subnet {cidr} to the scope.";
            AppendLog($"Detected local subnet: {cidr}");
        }
        catch (Exception ex) { StatusTextBlock.Text = "Local network information unavailable: " + ex.Message; }
    }

    private static string? DetectLocalCidr()
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                if (IPAddress.IsLoopback(ua.Address)) continue;

                int prefix = ua.PrefixLength;
                // Never invent a subnet when the platform cannot supply its prefix.
                if (prefix <= 0 || prefix > 32) continue;

                byte[] b = ua.Address.GetAddressBytes();
                uint ip = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
                uint mask = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
                uint network = ip & mask;

                return $"{(network >> 24) & 0xFF}.{(network >> 16) & 0xFF}.{(network >> 8) & 0xFF}.{network & 0xFF}/{prefix}";
            }
        }
        return null;
    }

    // ── Scan buttons ──────────────────────────────────────────────────────────

    private void OnScanAliveClick(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(ScopeTextBox.Text))
        {
            StatusTextBlock.Text = "Error: enter at least one target in the Scope panel.";
            ScopePanel.IsVisible = true;
            ScopeToggleBtn.Content = "Scope";
            ScopeToggleBtn.Classes.Set("active", true);
            ScopeTextBox.Focus();
            return;
        }

        if (!TryReadScanSettings(out int threads, out int timeout)) return;

        if (DiscoveryAttempts.Value is not decimal attempts || attempts != decimal.Truncate(attempts) || attempts < 1 || attempts > 3)
        {
            StatusTextBlock.Text = "Maximum discovery attempts must be 1, 2 or 3.";
            return;
        }

        _lastScanWasAlive = true;
        _discoveryComplete = false;
        _discoveryStartedAt = DateTimeOffset.UtcNow;
        _allDiscovery.Clear();
        _discoveryConfirmed = 0;
        AliveResults.Clear();
        FilterTextBox.Text = "";
        ResultsTabControl.SelectedIndex = 0;
        SetScanningState(true);
        ScanProgressBar.Value = 0;
        UpdateTabHeaders();
        AppendLog("--- Starting Host Discovery ---");

        var req = new
        {
            command = "alive",
            alive_config = new
            {
                Targets = ScopeTextBox.Text,
                Threads = threads,
                Timeout = timeout,
                Attempts = (int)attempts,
                EnableICMP = true,
                EnableTCP = true,
                EnableNetBIOS = true,
                EnableDNS = true,
                EnableARP = true,
                TCPPorts = new[] { 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 443, 445, 3389, 8080 }
            }
        };

        _discoveryConfig = req.alive_config;
        if (!_client.StartScan(req))
            SetScanningState(false);
    }

    private void OnScanSmbClick(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(ScopeTextBox.Text))
        {
            StatusTextBlock.Text = "Error: enter at least one target in the Scope panel.";
            ScopePanel.IsVisible = true;
            ScopeToggleBtn.Content = "Scope";
            ScopeToggleBtn.Classes.Set("active", true);
            ScopeTextBox.Focus();
            return;
        }

        if (!TryReadScanSettings(out int threads, out int timeout)) return;
        if (UseHashCheckBox.IsChecked == true && PortScanOnlyCheckBox.IsChecked != true &&
            (string.IsNullOrWhiteSpace(SmbUserTextBox.Text) ||
             !System.Text.RegularExpressions.Regex.IsMatch((SmbPassTextBox.Text ?? "").Trim(), @"\A[0-9a-fA-F]{32}\z")))
        {
            StatusTextBlock.Text = "Hash authentication requires a username and exactly 32 hexadecimal characters.";
            return;
        }

        _lastScanWasAlive = false;
        _smbComplete = false;
        _smbStartedAt = DateTimeOffset.UtcNow;
        _smbSettings = new SmbReportSettings(threads, timeout, PortScanOnlyCheckBox.IsChecked == true,
            EnableWMICheckBox.IsChecked == true, EnableSNMPCheckBox.IsChecked == true,
            SmbHostnamesCheckBox.IsChecked == true && PortScanOnlyCheckBox.IsChecked != true);
        _allSmb.Clear();
        _smbAdmin = _smbWritable = 0;
        SmbResults.Clear();
        _allUnreachable.Clear();
        UnreachableResults.Clear();
        FilterTextBox.Text = "";
        ResultsTabControl.SelectedIndex = 1;
        SetScanningState(true);
        ScanProgressBar.Value = 0;
        UpdateTabHeaders();
        AppendLog("--- Starting SMB Enumeration ---");

        var req = new
        {
            command = "smb",
            scan_config = new
            {
                Targets = ScopeTextBox.Text,
                Username = SmbUserTextBox.Text ?? "",
                Password = SmbPassTextBox.Text ?? "",
                Domain = SmbDomainTextBox.Text ?? "",
                UseHash = UseHashCheckBox.IsChecked ?? false,
                Threads = threads,
                Timeout = timeout,
                PortScanOnly = PortScanOnlyCheckBox.IsChecked ?? false,
                ResolveHostnames = _smbSettings.ResolveHostnames,
                EnableWMI = EnableWMICheckBox.IsChecked ?? false,
                EnableSNMP = EnableSNMPCheckBox.IsChecked ?? false,
                SNMPCommunity = string.IsNullOrWhiteSpace(SNMPCommunityTextBox.Text)
                                    ? "public" : SNMPCommunityTextBox.Text
            }
        };

        if (!_client.StartScan(req))
            SetScanningState(false);
    }

    private void OnStopClick(object? sender, RoutedEventArgs e)
    {
        _client.Stop();
        SetScanningState(false);
        StatusTextBlock.Text = "Scan stopped.";
        AppendLog("--- Scan stopped by user ---");
    }

    // ── Browse SMB shares in Dolphin (double-click) ──────────────────────────

    // Double-click a share chip → open that specific share.
    private void OnShareChipDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (sender is Control c && c.DataContext is ShareInfo share)
        {
            e.Handled = true; // don't also fire the row-level handler
            if (share.CanOpenInFileManager) OpenSmb(share.IP, share.Name);
        }
    }

    private void OnShareChipKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && e.KeyModifiers == KeyModifiers.None && sender is Control { DataContext: ShareInfo share })
        {
            e.Handled = true;
            if (share.CanOpenInFileManager) OpenSmb(share.IP, share.Name);
        }
    }

    // Double-click a host row (not on a chip) → open the server root to browse all shares.
    private void OnSmbRowDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (SmbDataGrid.SelectedItem is SmbResult r)
            OpenSmb(r.IP, null);
    }

    private async void OpenSmb(string ip, string? share)
    {
        try
        {
            string display = ShareLinks.Unc(ip, share);
            string url = ShareLinks.Url(ip, share);
            StatusTextBlock.Text = $"Opening {display} in the file manager…";
            AppendLog($"Opening {display}");
            if (OperatingSystem.IsWindows())
            {
                using var process = Process.Start(new ProcessStartInfo { FileName = display, UseShellExecute = true });
                return;
            }
            if (OperatingSystem.IsLinux() && !string.IsNullOrWhiteSpace(SmbUserTextBox.Text))
            {
                bool useHash = UseHashCheckBox.IsChecked == true;
                string authenticatedUrl = ShareLinks.DolphinUrl(ip, share, SmbUserTextBox.Text,
                    SmbPassTextBox.Text, SmbDomainTextBox.Text, useHash);
                try
                {
                    await _dolphin.OpenAsync(authenticatedUrl, _windowLifetime.Token);
                    StatusTextBlock.Text = useHash
                        ? $"Sent {display} to Dolphin. Hash mode requires a password or a saved Dolphin session."
                        : $"Sent {display} to Dolphin using the credentials in Settings.";
                }
                catch (OperationCanceledException) when (_windowLifetime.IsCancellationRequested) { }
                catch (Exception)
                {
                    // D-Bus errors can include the original request. Do not
                    // expose exception text or silently fall back to guest.
                    StatusTextBlock.Text = "Could not send the share to Dolphin. Check that Dolphin and the desktop session bus are available, then retry.";
                }
                return;
            }
            foreach (string command in new[] { "dolphin", "xdg-open" })
            {
                try
                {
                    var info = new ProcessStartInfo { FileName = command, UseShellExecute = false };
                    info.ArgumentList.Add(url);
                    using var process = Process.Start(info);
                    return;
                }
                catch (System.ComponentModel.Win32Exception) { }
            }
            StatusTextBlock.Text = "Could not launch a file manager (dolphin or xdg-open required).";
        }
        catch (Exception ex) { StatusTextBlock.Text = "Could not open share: " + ex.Message; }
    }

    // Double-click an alive host → open its SMB root in Dolphin.
    private void OnAliveRowDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (AliveDataGrid.SelectedItem is AliveResult r)
            OpenSmb(r.IP, null);
    }

    // ── Share chip context menu ──────────────────────────────────────────────

    private void OnShareOpenClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Control c && c.DataContext is ShareInfo s && s.CanOpenInFileManager)
            OpenSmb(s.IP, s.Name);
    }

    private async void OnShareCopyUncClick(object? sender, RoutedEventArgs e)
    {
        if (sender is Control c && c.DataContext is ShareInfo s)
            await CopyToClipboard($@"\\{s.IP}\{s.Name}");
    }

    private async void OnShareCopySmbClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (sender is Control c && c.DataContext is ShareInfo s)
                await CopyToClipboard(ShareLinks.Url(s.IP, s.Name));
        }
        catch (Exception ex) { StatusTextBlock.Text = "Operation failed: " + ex.Message; }
    }

    // ── Grid row context menu ────────────────────────────────────────────────

    // Resolve which row was right-clicked so the shared menu handlers can act on it.
    private void OnDataGridContextRequested(object? sender, ContextRequestedEventArgs e)
    {
        _ctxItem = null;
        if (e.Source is Control ctrl)
        {
            var row = ctrl.FindAncestorOfType<DataGridRow>(includeSelf: true);
            if (row?.DataContext != null)
            {
                _ctxItem = row.DataContext;
                if (sender is DataGrid g) g.SelectedItem = row.DataContext;
            }
        }
        // Keyboard context menus have no pointer row; use the selected item.
        if (_ctxItem == null && e.TryGetPosition(sender as Control, out _) == false && sender is DataGrid grid)
            _ctxItem = grid.SelectedItem;
    }

    private string? CtxIp() => _ctxItem switch
    {
        AliveResult a => a.IP,
        SmbResult s => s.IP,
        _ => null
    };

    private async void OnCtxCopyIpClick(object? sender, RoutedEventArgs e)
    {
        var ip = CtxIp();
        if (ip != null) await CopyToClipboard(ip);
    }

    private async void OnCtxCopyHostnameClick(object? sender, RoutedEventArgs e)
    {
        string? host = _ctxItem switch
        {
            AliveResult a => a.Hostname,
            SmbResult s => s.Hostname,
            _ => null
        };
        if (!string.IsNullOrEmpty(host)) await CopyToClipboard(host);
        else StatusTextBlock.Text = "No hostname for this host.";
    }

    private async void OnCtxCopyMacClick(object? sender, RoutedEventArgs e)
    {
        if (_ctxItem is AliveResult a && !string.IsNullOrEmpty(a.MACAddress))
            await CopyToClipboard(a.MACAddress);
        else
            StatusTextBlock.Text = "No MAC address for this host.";
    }

    private async void OnCtxCopyUncHostClick(object? sender, RoutedEventArgs e)
    {
        var ip = CtxIp();
        if (ip != null) await CopyToClipboard($@"\\{ip}");
    }

    private async void OnCtxCopyErrorClick(object? sender, RoutedEventArgs e)
    {
        if (_ctxItem is SmbResult s && !string.IsNullOrEmpty(s.Diagnostics))
            await CopyToClipboard(s.Diagnostics);
    }

    private void OnCtxOpenServerClick(object? sender, RoutedEventArgs e)
    {
        var ip = CtxIp();
        if (ip != null) OpenSmb(ip, null);
    }

    // Append the right-clicked host's IP to the Scope panel (for a follow-up SMB scan).
    private void OnCtxScopeThisClick(object? sender, RoutedEventArgs e)
    {
        var ip = CtxIp();
        if (ip == null) return;

        string existing = ScopeTextBox.Text ?? "";
        if (existing.Split('\n').Any(l => l.Trim() == ip))
        {
            StatusTextBlock.Text = $"{ip} is already in the scope.";
        }
        else
        {
            ScopeTextBox.Text = string.IsNullOrWhiteSpace(existing) ? ip : existing.TrimEnd('\n') + "\n" + ip;
            UpdateScopeCount();
            StatusTextBlock.Text = $"Added {ip} to the scope.";
        }
        ScopePanel.IsVisible = true;
        ScopeToggleBtn.Content = "Scope";
        ScopeToggleBtn.Classes.Set("active", true);
    }

    private async System.Threading.Tasks.Task CopyToClipboard(string text)
    {
        var clip = TopLevel.GetTopLevel(this)?.Clipboard;
        if (clip == null) { StatusTextBlock.Text = "Clipboard is unavailable in this desktop session."; return; }
        try
        {
            await clip.SetTextAsync(text);
            StatusTextBlock.Text = "Copied to clipboard.";
        }
        catch (Exception ex) { StatusTextBlock.Text = "Clipboard unavailable: " + ex.Message; }
    }

    // ── Utility ───────────────────────────────────────────────────────────────

    private void OnLogToggleClick(object? sender, RoutedEventArgs e)
    {
        LogContent.IsVisible = !LogContent.IsVisible;
        LogToggleBtn.Content = LogContent.IsVisible ? "Hide log" : "Show log";
    }

    private void OnClearLogClick(object? sender, RoutedEventArgs e)
    {
        _log.Clear();
        _pendingLogOffset = default(Avalonia.Vector);
        _followLogTail = true;
        _pendingLogRemovedLines = 0;
        LogTextBox.Text = "";
    }

    private async void OnExportCsvClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            int tab = ResultsTabControl.SelectedIndex; // 0 = alive, 1 = SMB, 2 = unreachable
            string suggested = tab switch
            {
                0 => "host_discovery.csv",
                2 => "unreachable.csv",
                _ => "smb_shares.csv"
            };

            // Capture this scan before the dialog yields to other UI activity.
            var sb = new StringBuilder();

            if (tab == 0)
            {
                sb.AppendLine("IP Address,Status,IsAlive,Hostname,MAC Address,Vendor,ICMP Latency,Open TCP Ports,Detection Method,Attempts,Checked At,Diagnostics");
                foreach (var r in _allDiscovery)
                    sb.AppendLine(ExportSupport.Csv(r.IP, r.Status, r.IsAlive.ToString(), r.Hostname, r.MACAddress, r.MACVendor,
                                      r.ICMPLatency, r.OpenPortsList, r.DetectionMethod, r.Attempts.ToString(), r.CheckedAt, r.Diagnostics));
            }
            else if (tab == 2)
            {
                sb.AppendLine("IP Address,Hostname,Reason,TCP Attempts,TCP Failures");
                foreach (var r in _allUnreachable)
                    sb.AppendLine(ExportSupport.Csv(r.IP, r.Hostname, r.Error, r.ConnectionAttempts.ToString(), string.Join("; ", r.ConnectionErrors)));
            }
            else
            {
                sb.AppendLine("IP Address,Hostname,Auth/Status,SMB Version,OS/Version,Admin Share Access,Shares,Share Details,WMI Metadata,SNMP Metadata,Diagnostics,Enumeration Status,TCP Attempts,TCP Failures");
                foreach (var r in _allSmb)
                    sb.AppendLine(ExportSupport.Csv(r.IP, r.Hostname, r.SessionLabel, r.SMBVersion, r.OSVersion,
                                      r.IsAdmin ? "Yes" : "No",
                                      r.SharesSummary, r.ShareDetails, r.WMIInfo, r.SNMPInfo, r.Diagnostics, r.EnumerationStatus,
                                      r.ConnectionAttempts.ToString(), string.Join("; ", r.ConnectionErrors)));
            }

            var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Export Results as CSV",
                DefaultExtension = "csv",
                SuggestedFileName = suggested,
                FileTypeChoices = new[]
                {
                new FilePickerFileType("CSV Files") { Patterns = new[] { "*.csv" } }
            }
            });

            if (file == null) return;

            await using var stream = await file.OpenWriteAsync();
            await ExportSupport.WriteTextAsync(stream, sb.ToString());

            StatusTextBlock.Text = $"Exported: {file.Name}";
            AppendLog($"Results exported: {file.Name}");
        }
        catch (Exception ex) { StatusTextBlock.Text = "Operation failed: " + ex.Message; }
    }

    private void OnExportMenuClick(object? sender, RoutedEventArgs e) =>
        ExportResultsBtn.ContextMenu?.Open(ExportResultsBtn);

    private async void OnExportAliveTxtClick(object? sender, RoutedEventArgs e) => await ExportAliveIPsAsync(false);

    private async void OnExportAliveJsonClick(object? sender, RoutedEventArgs e) => await ExportAliveIPsAsync(true);

    private async System.Threading.Tasks.Task ExportAliveIPsAsync(bool json)
    {
        try
        {
            if (!_discoveryComplete)
            {
                StatusTextBlock.Text = "Finish Host Discovery before exporting alive IPs. Partial results are available in the discovery report.";
                return;
            }
            // Snapshot the whole completed scan, independent of the active tab,
            // text filter and visibility of unconfirmed diagnostic rows.
            string[] ips = ExportSupport.ConfirmedIPs(_allDiscovery);
            string extension = json ? "json" : "txt";
            var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = json ? "Export alive IPs as JSON" : "Export alive IPs as text",
                DefaultExtension = extension,
                SuggestedFileName = $"alive_ips_{_discoveryStartedAt:yyyyMMdd_HHmmss}.{extension}",
                FileTypeChoices = new[] { new FilePickerFileType(json ? "JSON IP list" : "Text IP list") { Patterns = new[] { "*." + extension } } }
            });
            if (file == null) return;
            string text = json
                ? System.Text.Json.JsonSerializer.Serialize(ips, new System.Text.Json.JsonSerializerOptions { WriteIndented = true })
                : ips.Length == 0 ? "" : string.Join("\n", ips) + "\n";
            await using var stream = await file.OpenWriteAsync();
            // No BOM, headings or metadata: TXT can be passed directly to Nmap -iL.
            await ExportSupport.WriteTextAsync(stream, text, includeBom: false);
            StatusTextBlock.Text = $"Exported {ips.Length} confirmed {(ips.Length == 1 ? "IP" : "IPs")}: {file.Name}";
            AppendLog(StatusTextBlock.Text);
        }
        catch (Exception ex) { StatusTextBlock.Text = "Operation failed: " + ex.Message; }
    }

    private void OnDiscoveryVisibilityChanged(object? sender, RoutedEventArgs e)
    {
        if (AliveDataGrid != null && FilterTextBox != null) ApplyFilter();
    }

    private async void OnExportSmbReportClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (_smbSettings == null || _smbStartedAt == null) { StatusTextBlock.Text = "Run an SMB scan before exporting a report."; return; }
            // Snapshot before opening the dialog: a scan can continue while it is open.
            var report = SmbEvidenceReport.Create(_smbComplete, _smbStartedAt.Value, _smbSettings,
                _allSmb.Concat(_allUnreachable));
            var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Export SMB report",
                DefaultExtension = "json",
                SuggestedFileName = $"smb_report_{_smbStartedAt.Value:yyyyMMdd_HHmmss}.json",
                FileTypeChoices = new[] { new FilePickerFileType("JSON report") { Patterns = new[] { "*.json" } } }
            });
            if (file == null) return;
            await using var stream = await file.OpenWriteAsync();
            if (stream.CanSeek) { stream.Position = 0; stream.SetLength(0); }
            await System.Text.Json.JsonSerializer.SerializeAsync(stream, report,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            StatusTextBlock.Text = report.Completed ? "SMB report exported." : "Partial SMB report exported (scan not complete).";
        }
        catch (Exception ex) { StatusTextBlock.Text = "Operation failed: " + ex.Message; }
    }

    private async void OnExportDiscoveryReportClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            if (_discoveryConfig == null) { StatusTextBlock.Text = "Run Host Discovery before exporting a report."; return; }
            // Keep settings, completion state and results from the same scan.
            var report = new
            {
                SchemaVersion = 1,
                Completed = _discoveryComplete,
                StartedAt = _discoveryStartedAt,
                ExportedAt = DateTimeOffset.UtcNow,
                Config = _discoveryConfig,
                Results = _allDiscovery.ToArray()
            };
            var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Export discovery report",
                DefaultExtension = "json",
                SuggestedFileName = "host_discovery_report.json",
                FileTypeChoices = new[] { new FilePickerFileType("JSON report") { Patterns = new[] { "*.json" } } }
            });
            if (file == null) return;
            await using var stream = await file.OpenWriteAsync();
            if (stream.CanSeek) { stream.Position = 0; stream.SetLength(0); }
            await System.Text.Json.JsonSerializer.SerializeAsync(stream, report,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            StatusTextBlock.Text = report.Completed ? "Discovery report exported." : "Partial discovery report exported (scan not complete).";
        }
        catch (Exception ex) { StatusTextBlock.Text = "Operation failed: " + ex.Message; }
    }

}
