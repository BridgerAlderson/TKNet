using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;

namespace TKNetUI.VisualChecks;

internal static partial class PreviewProgram
{
    private static void RunExportSnapshotChecks()
    {
        var picker = new DeferredSavePicker();
        using var lifetime = new WindowLifetime();
        var window = lifetime.Window;
        typeof(TopLevel).GetField("_storageProvider", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(window, picker.Provider);
        window.Show();
        Assert(ReferenceEquals(window.StorageProvider, picker.Provider), "Export tests use an isolated, deferred file picker.");
        var discovery = GetField<List<AliveResult>>(window, "_allDiscovery");
        var smb = GetField<List<SmbResult>>(window, "_allSmb");
        var unreachable = GetField<List<SmbResult>>(window, "_allUnreachable");

        for (int tab = 0; tab < 3; tab++)
        {
            discovery.Clear(); smb.Clear(); unreachable.Clear();
            discovery.Add(new AliveResult { IP = "192.0.2.10", IsAlive = true });
            smb.Add(new SmbResult { IP = "192.0.2.10", Port445Open = true, Status = "Authenticated",
                Shares = new[] { new ShareInfo { Name = "print$", CanRead = true },
                    new ShareInfo { Name = "Incoming", ReadCheck = "Denied", WriteCheck = "Not checked",
                        AccessError = "Root listing denied. Write access was not checked." } } });
            unreachable.Add(new SmbResult { IP = "192.0.2.10", Error = "connection refused" });
            Find<TabControl>(window, "ResultsTabControl").SelectedIndex = tab;
            picker.Reset();
            Invoke(window, "OnExportCsvClick", window, new RoutedEventArgs());
            Assert(picker.Requested, "CSV export opens the picker before the simulated next scan.");
            discovery.Clear(); smb.Clear(); unreachable.Clear();
            discovery.Add(new AliveResult { IP = "198.51.100.20", IsAlive = true });
            smb.Add(new SmbResult { IP = "198.51.100.20", Port445Open = true });
            unreachable.Add(new SmbResult { IP = "198.51.100.20" });
            string csv = FinishExport(window, picker);
            Assert(csv.Contains("192.0.2.10") && !csv.Contains("198.51.100.20"),
                "CSV keeps the selected scan when data changes while the picker is open (tab " + tab + ").");
            if (tab == 1) Assert(csv.Contains("print$") && csv.Contains("Incoming[-?]") && csv.Contains("Configured credentials"),
                "SMB CSV retains disk shares, untested write access and the credential-source label.");
        }

        discovery.Clear();
        discovery.Add(new AliveResult { IP = "192.0.2.30", IsAlive = true });
        var started = DateTimeOffset.Parse("2026-10-22T10:00:00Z");
        SetField(window, "_discoveryStartedAt", (DateTimeOffset?)started);
        SetField(window, "_discoveryConfig", new { Targets = "192.0.2.30", Threads = 50 });
        SetField(window, "_discoveryComplete", true);
        picker.Reset();
        Invoke(window, "OnExportDiscoveryReportClick", window, new RoutedEventArgs());
        Assert(picker.Requested, "Discovery report opens the deferred picker.");
        discovery.Clear();
        discovery.Add(new AliveResult { IP = "198.51.100.40" });
        SetField(window, "_discoveryStartedAt", (DateTimeOffset?)started.AddHours(1));
        SetField(window, "_discoveryConfig", new { Targets = "198.51.100.40", Threads = 1 });
        SetField(window, "_discoveryComplete", false);
        using (var document = JsonDocument.Parse(FinishExport(window, picker)))
        {
            var report = document.RootElement;
            Assert(report.GetProperty("Completed").GetBoolean() && report.GetProperty("StartedAt").GetDateTimeOffset() == started,
                "Discovery JSON keeps the original completion state and start time.");
            Assert(report.GetProperty("Config").GetProperty("Targets").GetString() == "192.0.2.30" &&
                report.GetProperty("Results")[0].GetProperty("IP").GetString() == "192.0.2.30",
                "Discovery JSON keeps matching settings and results from the selected scan.");
        }

        smb.Clear(); unreachable.Clear();
        smb.Add(new SmbResult { IP = "192.0.2.50", Port445Open = true,
            Shares = new[] { new ShareInfo { Name = "print$", CanRead = true } } });
        SetField(window, "_smbStartedAt", (DateTimeOffset?)started);
        SetField(window, "_smbSettings", new SmbReportSettings(50, 10, false, false, false));
        SetField(window, "_smbComplete", true);
        picker.Reset();
        Invoke(window, "OnExportSmbReportClick", window, new RoutedEventArgs());
        Assert(picker.Requested, "SMB report opens the deferred picker.");
        smb.Clear();
        SetField(window, "_smbComplete", false);
        SetField(window, "_smbSettings", new SmbReportSettings(1, 1, true, false, false));
        using (var document = JsonDocument.Parse(FinishExport(window, picker)))
        {
            var report = document.RootElement;
            Assert(report.GetProperty("Completed").GetBoolean() && report.GetProperty("Config").GetProperty("Threads").GetInt32() == 50,
                "SMB JSON preserves its original completion and settings snapshot.");
            Assert(report.GetProperty("Results")[0].GetProperty("Shares")[0].GetProperty("Name").GetString() == "print$",
                "SMB JSON retains the known share list after another scan clears the view.");
        }

        Find<TextBox>(window, "ScopeTextBox").Text = "192.0.2.0/24";
        picker.Reset();
        Invoke(window, "OnScopeSaveClick", window, new RoutedEventArgs());
        Assert(picker.Requested, "Scope save opens the deferred picker.");
        Find<TextBox>(window, "ScopeTextBox").Text = "198.51.100.0/24";
        Assert(FinishExport(window, picker) == "192.0.2.0/24", "Scope save keeps the scope selected when Save was clicked.");

        picker.Reset();
        Invoke(window, "OnExportCsvClick", window, new RoutedEventArgs());
        picker.Complete(null);
        Flush(window);
        Assert(!Find<TextBlock>(window, "StatusTextBlock").Text!.StartsWith("Operation failed:"),
            "Cancelling the save dialog is not an export error.");

        picker.Reset();
        Invoke(window, "OnExportCsvClick", window, new RoutedEventArgs());
        picker.Complete(new MemoryExportFile { FailWrite = true }.File);
        WaitForExport(window, "Operation failed:");
        Assert(Find<TextBlock>(window, "StatusTextBlock").Text!.Contains("synthetic write failure"),
            "Export reports a write failure instead of claiming success.");
    }

    private static string FinishExport(MainWindow window, DeferredSavePicker picker)
    {
        var file = new MemoryExportFile();
        Find<TextBlock>(window, "StatusTextBlock").Text = "Waiting for test export";
        picker.Complete(file.File);
        WaitForExport(window, null);
        Assert(!Find<TextBlock>(window, "StatusTextBlock").Text!.StartsWith("Operation failed:"), "The deferred export completes successfully.");
        string text = Encoding.UTF8.GetString(file.Content.ToArray()).TrimStart('\uFEFF');
        Assert(!text.Contains("stale suffix"), "Export replaces existing file contents without a stale suffix.");
        return text;
    }

    private static void WaitForExport(MainWindow window, string? prefix)
    {
        var timer = Stopwatch.StartNew();
        while (timer.Elapsed < TimeSpan.FromSeconds(5))
        {
            Flush(window);
            string status = Find<TextBlock>(window, "StatusTextBlock").Text ?? "";
            if (prefix == null ? status != "Waiting for test export" : status.StartsWith(prefix)) return;
            Thread.Sleep(5);
        }
        throw new InvalidOperationException("Export handler did not finish.");
    }

    // Avalonia marks its reference-assembly storage interfaces as non-implementable
    // in C#. A runtime proxy replaces only this test window's storage service.
    public class StorageProxy : DispatchProxy
    {
        public Func<string, object?[]?, object?> Call { get; set; } = (_, _) => throw new NotSupportedException();
        protected override object? Invoke(MethodInfo? method, object?[]? args) => Call(method!.Name, args);
    }

    private static T StorageStub<T>(Func<string, object?[]?, object?> call) where T : class
    {
        var stub = DispatchProxy.Create<T, StorageProxy>();
        ((StorageProxy)(object)stub).Call = call;
        return stub;
    }

    private sealed class DeferredSavePicker
    {
        private TaskCompletionSource<IStorageFile?> _selection = new();
        public IStorageProvider Provider { get; }
        public FilePickerSaveOptions? Options { get; private set; }
        public bool Requested { get; private set; }
        public DeferredSavePicker() => Provider = StorageStub<IStorageProvider>((method, args) =>
        {
            if (method == "SaveFilePickerAsync") { Requested = true; Options = (FilePickerSaveOptions)args![0]!; return _selection.Task; }
            return method switch
            {
                "get_CanSave" => true,
                "get_CanOpen" or "get_CanPickFolder" => false,
                _ => throw new NotSupportedException(method)
            };
        });
        public void Reset() { _selection = new(); Requested = false; Options = null; }
        public void Complete(IStorageFile? file) => _selection.SetResult(file);
    }

    private sealed class MemoryExportFile
    {
        public MemoryStream Content { get; } = new();
        public IStorageFile File { get; }
        public bool FailWrite { get; init; }
        public MemoryExportFile() => File = StorageStub<IStorageFile>((method, _) => method switch
        {
            "get_Name" => "isolated-test-export",
            "OpenWriteAsync" => OpenWriteAsync(),
            _ => throw new NotSupportedException(method)
        });
        private Task<Stream> OpenWriteAsync()
        {
            if (FailWrite) throw new IOException("synthetic write failure");
            Content.Write(Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("stale suffix", 500))));
            return Task.FromResult<Stream>(Content);
        }
    }
}
