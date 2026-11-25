using System.Reflection;
using Avalonia.Controls;
using Avalonia.VisualTree;

namespace TKNetUI.VisualChecks;

internal static partial class PreviewProgram
{
    private static void RunSmbCompletenessChecks(string output)
    {
        using var lifetime = new WindowLifetime();
        var window = lifetime.Window;
        window.Width = 1400;
        window.Height = 900;
        window.Show();
        var hostnames = Find<CheckBox>(window, "SmbHostnamesCheckBox");
        var portOnly = Find<CheckBox>(window, "PortScanOnlyCheckBox");
        Assert(hostnames.IsChecked != true && hostnames.IsEnabled, "SMB hostname lookup is optional.");
        portOnly.IsChecked = true;
        Flush(window);
        Assert(!hostnames.IsEnabled, "Port-only mode disables post-session hostname lookup.");
        portOnly.IsChecked = false;
        SelectTab(window, "SmbTab");
        typeof(MainWindow).GetField("_lastScanWasAlive", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(window, false);
        Invoke(window, "SetScanningState", true);
        var results = new[]
        {
            new SmbResult
            {
                IP = "192.0.2.20", Port445Open = true, Status = "Authenticated", EnumerationStatus = "Partial",
                Shares = new[]
                {
                    new ShareInfo { Name = "Team", CanRead = true, AccessError = "Write check timed out" },
                    new ShareInfo { Name = "Restricted$", ReadCheck = "Denied", WriteCheck = "Not checked",
                        AccessError = "Root listing denied. Write access was not checked." },
                    new ShareInfo { Name = "Denied$" }
                }
            },
            new SmbResult { IP = "192.0.2.21", Port445Open = true, Status = "Guest Session",
                EnumerationStatus = "Complete", Warnings = new[] { "Configured authentication failed; guest fallback was used" },
                Shares = new[] { new ShareInfo { Name = "Office printer", ShareType = 1 } } },
            new SmbResult { IP = "192.0.2.22", Port445Open = true, Status = "Authenticated",
                EnumerationStatus = "Failed", Error = "Enumeration timed out" },
            new SmbResult { IP = "192.0.2.23", Port445Open = true, EnumerationStatus = "Not attempted" }
        };
        var client = GetField<EngineClient>(window, "_client");
        var receive = (Action<SmbResult>)typeof(EngineClient)
            .GetField("OnSmbResult", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(client)!;
        var complete = (Action)typeof(EngineClient)
            .GetField("OnDone", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(client)!;
        foreach (var result in results) { result.Normalize(); receive(result); }
        complete();
        Flush(window);

        Assert(window.SmbResults.Count == results.Length && window.SmbResults[0].Shares.Length == 3,
            "The real SMB event handlers retain all hosts and denied/inconclusive shares before completion.");
        Assert(Find<Button>(window, "ScanSmbBtn").IsEnabled && !Find<Button>(window, "StopBtn").IsEnabled,
            "SMB completion restores the scan controls after delivering results.");
        var status = Find<TextBlock>(window, "StatusTextBlock");
        string summary = status.Text ?? "";
        Assert(summary.Contains("4 shares") && summary.Contains("4 reachable") && summary.Contains("4 hosts to review"),
            "The compact completion status retains share counts and flags every host needing review.");
        string details = ToolTip.GetTip(status)?.ToString() ?? "";
        Assert(details.Contains("2 hosts with incomplete checks or errors") &&
            details.Contains("1 host with warnings") && details.Contains("1 host not enumerated") &&
            Find<TextBox>(window, "LogTextBox").Text?.Contains(details) == true,
            "The completion tooltip and Activity log retain the full enumeration and access diagnostics.");
        var grid = Find<DataGrid>(window, "SmbDataGrid");
        var chips = grid.GetVisualDescendants().OfType<Border>().Where(c => c.Classes.Contains("sharechip")).ToArray();
        foreach (var share in results[0].Shares)
        {
            var chip = chips.Single(c => ReferenceEquals(c.DataContext, share));
            Assert(chip.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == share.Access),
                "The production share chip distinguishes confirmed denial, partial access and unchecked access.");
            if (share.HasAccessError)
                Assert(ToolTip.GetTip(chip)?.ToString()?.Contains(share.AccessError) == true,
                    "The production share tooltip retains the reason an access check is inconclusive.");
        }
        var printer = chips.Single(c => ReferenceEquals(c.DataContext, results[1].Shares[0]));
        Assert(printer.GetVisualDescendants().OfType<TextBlock>().Any(t => t.Text == "Printer") &&
            ToolTip.GetTip(printer)?.ToString()?.Contains("do not apply") == true,
            "Printer shares remain visible without false file-permission errors.");
        printer.ContextMenu!.Open(printer);
        Flush(window);
        Assert(!printer.ContextMenu.Items.OfType<MenuItem>().First().IsEnabled,
            "A non-file share cannot launch a file-manager open action.");
        printer.ContextMenu.Close();
        Capture(window, output, "19-smb-incomplete-1400x900", 1400, 900);
        Capture(window, output, "20-smb-incomplete-900x550", 900, 550);
        Find<TextBox>(window, "FilterTextBox").Text = "Write check timed out";
        Flush(window);
        Assert(window.SmbResults.Count == 1 && ReferenceEquals(window.SmbResults[0], results[0]) &&
            window.SmbResults[0].Shares.Length == 3,
            "Filtering by a share check failure preserves the complete host and share identities.");
        Find<TextBox>(window, "FilterTextBox").Text = "";
        Flush(window);
        Assert(window.SmbResults.SequenceEqual(results), "Clearing the failure filter restores every SMB host.");
        status.Text = "Scope saved: targets.txt";
        Assert(ToolTip.GetTip(status)?.ToString() == status.Text,
            "New activity replaces the previous scan's tooltip without showing stale diagnostics.");
        Assert(client.ScanId == 0, "SMB completion fixtures never launch an engine or authenticate.");
    }
}
