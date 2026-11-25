using System.Reflection;
using System.Text;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Interactivity;

namespace TKNetUI.VisualChecks;

internal static partial class PreviewProgram
{
    private static void RunDiscoveryTargetChecks(string output)
    {
        using var lifetime = new WindowLifetime();
        var window = lifetime.Window;
        var picker = new DeferredSavePicker();
        typeof(TopLevel).GetField("_storageProvider", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(window, picker.Provider);
        window.Show();
        var menu = Find<Button>(window, "ExportResultsBtn").ContextMenu!;
        var txt = menu.Items.OfType<MenuItem>().Single(item => item.Name == "ExportAliveTxtMenu");
        var json = menu.Items.OfType<MenuItem>().Single(item => item.Name == "ExportAliveJsonMenu");
        Assert(!txt.IsEnabled && !json.IsEnabled, "Alive export is unavailable before discovery completes.");
        var client = GetField<EngineClient>(window, "_client");
        var receive = (Action<AliveResult>)typeof(EngineClient)
            .GetField("OnAliveResult", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(client)!;
        var done = (Action)typeof(EngineClient)
            .GetField("OnDone", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(client)!;
        var results = new[]
        {
            new AliveResult { IP = "192.0.2.10", IsAlive = true, Status = "Confirmed", ICMPAlive = true, DetectionMethod = "ICMP" },
            new AliveResult { IP = "192.0.2.9", IsAlive = true, Status = "Confirmed", TCPOpenPorts = new[] { 445 }, DetectionMethod = "TCP:445", Warnings = new[] { "ARP tool unavailable" } },
            new AliveResult { IP = "192.0.2.11", Status = "Unconfirmed (ARP only)", ARPObserved = true },
            new AliveResult { IP = "192.0.2.12", Status = "Unconfirmed (TCP refusal)", TCPRefusedPorts = new[] { 445 } },
            new AliveResult { IP = "192.0.2.13", Status = "No response", DNSName = "stale.example.test" },
            new AliveResult { IP = "192.0.2.14", Status = "Incomplete (probe errors)", Error = "No probe permission" },
            new AliveResult { IP = "192.0.2.15", Status = "Cancelled" }
        };
        SetField(window, "_discoveryStartedAt", (DateTimeOffset?)DateTimeOffset.Parse("2026-10-23T09:00:00Z"));
        Invoke(window, "SetScanningState", true);
        foreach (var result in results) { result.Normalize(); receive(result); }
        Flush(window);
        Assert(window.AliveResults.Count == 2 && window.AliveResults.All(result => result.IsAlive),
            "Real result delivery shows only confirmed hosts, including one with an optional probe warning.");
        Assert(!txt.IsEnabled && !json.IsEnabled, "Receiving confirmed hosts does not make an unfinished scan exportable as complete.");
        Invoke(window, "OnExportAliveTxtClick", window, new RoutedEventArgs());
        Assert(!picker.Requested, "The actual export handler rejects an unfinished or stopped discovery.");
        done();
        Flush(window);
        Assert(txt.IsEnabled && json.IsEnabled, "A completed discovery enables both IP-only formats.");
        Find<Button>(window, "ExportResultsBtn").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Flush(window);
        Assert(menu.IsOpen && menu.Items.OfType<MenuItem>().Count() == 3, "The export button exposes CSV, alive TXT and alive JSON.");
        menu.Close();
        Capture(window, output, "22-confirmed-hosts-900x550", 900, 550);

        Find<CheckBox>(window, "ShowAllDiscoveryCheckBox").IsChecked = true;
        Flush(window);
        Assert(window.AliveResults.Count == results.Length, "All checked addresses remain available for diagnostics.");
        Find<CheckBox>(window, "ShowAllDiscoveryCheckBox").IsChecked = false;
        Flush(window);
        Assert(window.AliveResults.Count == 2, "Returning to the default view removes all unconfirmed rows.");

        var all = GetField<List<AliveResult>>(window, "_allDiscovery");
        foreach (bool asJson in new[] { false, true })
        {
            all.Clear(); all.AddRange(results); all.Add(results[0]);
            SetField(window, "_discoveryComplete", true);
            Find<CheckBox>(window, "ShowAllDiscoveryCheckBox").IsChecked = true;
            Find<TextBox>(window, "FilterTextBox").Text = "stale.example.test";
            Flush(window);
            Assert(window.AliveResults.Count == 1 && !window.AliveResults[0].IsAlive, "The visible filtered row is deliberately unconfirmed.");
            // Active SMB tab and UI filters must not change the discovery export.
            SelectTab(window, "SmbTab");
            picker.Reset();
            (asJson ? json : txt).RaiseEvent(new RoutedEventArgs(MenuItem.ClickEvent));
            Assert(picker.Requested, "The real menu item opens the selected IP export.");
            Assert(picker.Options?.DefaultExtension == (asJson ? "json" : "txt") &&
                picker.Options.SuggestedFileName == "alive_ips_20261023_090000." + (asJson ? "json" : "txt"),
                "IP export selects the requested format and identifies the completed discovery time.");
            all.Clear(); all.Add(new AliveResult { IP = "198.51.100.99", IsAlive = true });
            SetField(window, "_discoveryComplete", false);
            Find<TextBlock>(window, "StatusTextBlock").Text = "Waiting for test export";
            var file = new MemoryExportFile();
            picker.Complete(file.File);
            WaitForExport(window, null);
            byte[] bytes = file.Content.ToArray();
            Assert(!bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }), "IP export contains no UTF-8 BOM.");
            string text = Encoding.UTF8.GetString(bytes);
            string[] ips = asJson ? JsonSerializer.Deserialize<string[]>(text)! : text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            Assert(ips.SequenceEqual(new[] { "192.0.2.9", "192.0.2.10" }),
                "Export contains exactly the sorted unique confirmed IPs, independent of filters and a subsequent scan.");
            if (!asJson) Assert(text == "192.0.2.9\n192.0.2.10\n", "TXT is directly usable as a line-delimited target list.");
            File.WriteAllBytes(Path.Combine(output, asJson ? "alive_ips.json" : "alive_ips.txt"), bytes);
            Assert(Find<TextBlock>(window, "StatusTextBlock").Text!.StartsWith("Exported 2 confirmed IPs:"), "Export reports the count actually written.");
        }

        all.Clear(); all.Add(results[2]);
        SetField(window, "_discoveryComplete", true);
        foreach (string handler in new[] { "OnExportAliveTxtClick", "OnExportAliveJsonClick" })
        {
            picker.Reset();
            Invoke(window, handler, window, new RoutedEventArgs());
            string text = FinishExport(window, picker);
            Assert(text == (handler.Contains("Json") ? "[]" : ""), "A completed scan without confirmed hosts exports an empty list.");
        }
        picker.Reset();
        Invoke(window, "OnExportAliveTxtClick", window, new RoutedEventArgs());
        string beforeCancel = Find<TextBlock>(window, "StatusTextBlock").Text!;
        picker.Complete(null); Flush(window);
        Assert(Find<TextBlock>(window, "StatusTextBlock").Text == beforeCancel, "Cancelling an alive-IP export does not report a completed write.");
        picker.Reset();
        Invoke(window, "OnExportAliveJsonClick", window, new RoutedEventArgs());
        picker.Complete(new MemoryExportFile { FailWrite = true }.File);
        WaitForExport(window, "Operation failed:");
        Assert(Find<TextBlock>(window, "StatusTextBlock").Text!.Contains("synthetic write failure"), "IP export surfaces a write failure.");
        Assert(client.ScanId == 0, "Discovery export and visibility checks never start the network engine.");
    }
}
