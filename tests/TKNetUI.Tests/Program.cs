using TKNetUI;

if (args.Length == 2 && args[0] == "--fake-dolphin")
{
    await DolphinDbusChecks.RunFakeAsync(args[1]);
    return;
}

int assertions = 0;
void Assert(bool condition, string message) { assertions++; if (!condition) throw new Exception(message); }
using (var fixtures = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "scopes.json"))))
foreach (var fixture in fixtures.RootElement.EnumerateArray())
{
    string scope = fixture.GetProperty("input").GetString()!;
    var summary = ScopeParser.Analyze(scope);
    if (fixture.GetProperty("valid").GetBoolean())
        Assert(summary.InvalidLines == 0 && summary.Hosts == fixture.GetProperty("count").GetInt64(),
            $"Scope mismatch: {scope}: {summary.Hosts} / {summary.FirstError}");
    else
        Assert(summary.InvalidLines > 0, "Invalid scope accepted: " + scope);
}

// Export and presentation checks use memory streams and synthetic metadata.
Assert(ExportSupport.Csv("a,b", "a\"b", "a\rb") == "\"a,b\",\"a\"\"b\",\"a\rb\"", "CSV escaping is incomplete");
foreach (string input in new[] { "=1+1", "+1", "-1", "@name", "  =1", "\tlabel" })
    Assert(ExportSupport.Csv(input) == "'" + input, "CSV formula was not neutralized");
Assert(ExportSupport.Csv("server-name", null) == "server-name,", "ordinary CSV data changed");
var confirmedIPs = ExportSupport.ConfirmedIPs(new[]
{
    new AliveResult { IP = "192.0.2.10", IsAlive = true },
    new AliveResult { IP = "192.0.2.9", IsAlive = true, Warnings = new[] { "Optional ARP unavailable" } },
    new AliveResult { IP = "192.0.2.10", IsAlive = true },
    new AliveResult { IP = "192.0.2.11", ARPObserved = true },
    new AliveResult { IP = "192.0.2.12", TCPRefusedPorts = new[] { 445 } },
    new AliveResult { IP = "192.0.2.13", DNSName = "stale.example.test" },
    new AliveResult { IP = "192.0.2.14", Error = "No probe permission" },
    new AliveResult { IP = "192.0.2.15", Status = "Confirmed" },
    new AliveResult { IP = "192.0.2.16", Status = "No response" }
});
Assert(confirmedIPs.SequenceEqual(new[] { "192.0.2.9", "192.0.2.10" }),
    "Alive target export must exclude unconfirmed results, keep confirmed hosts with optional probe warnings, deduplicate and sort numerically");
Assert(ExportSupport.ConfirmedIPs(Array.Empty<AliveResult>()).Length == 0, "An empty discovery produced targets");
foreach (string invalid in new[] { "192.0.2.10\n198.51.100.1", "127.1", "host.example.test", "::1", "192.0.2.0/24" })
{
    bool rejected = false;
    try { ExportSupport.ConfirmedIPs(new[] { new AliveResult { IP = invalid, IsAlive = true } }); }
    catch (InvalidDataException) { rejected = true; }
    Assert(rejected, "Malformed confirmed target could inject an extra host or scope");
}
using (var stream = new MemoryStream())
{
    await ExportSupport.WriteTextAsync(stream, new string('x', 500));
    await ExportSupport.WriteTextAsync(stream, string.Join("\n", confirmedIPs) + "\n", includeBom: false);
    Assert(stream.ToArray().SequenceEqual(System.Text.Encoding.UTF8.GetBytes("192.0.2.9\n192.0.2.10\n")),
        "IP-only TXT contains a BOM, metadata, separators or stale file contents");
    await ExportSupport.WriteTextAsync(stream, "", includeBom: false);
    Assert(stream.Length == 0, "Empty target list retained old addresses");
}
using (var stream = new MemoryStream())
{
    await ExportSupport.WriteTextAsync(stream, new string('x', 500));
    await ExportSupport.WriteTextAsync(stream, "short");
    stream.Position = 0;
    using var reader = new StreamReader(stream);
    Assert(await reader.ReadToEndAsync() == "short", "old file tail survived overwrite");
}
using (var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes("192.0.2.1\n")))
    Assert(await ExportSupport.ReadScopeAsync(stream) == "192.0.2.1\n", "scope file changed");
using (var stream = new MemoryStream(new byte[ExportSupport.MaxScopeCharacters + 1]))
{
    bool rejected = false;
    try { await ExportSupport.ReadScopeAsync(stream); } catch (InvalidDataException) { rejected = true; }
    Assert(rejected, "oversized scope file accepted");
}
Assert(ShareLinks.Url("192.0.2.1", "Team #1") == "smb://192.0.2.1/Team%20%231", "share URL not encoded");
Assert(ShareLinks.Unc("192.0.2.1", "C$") == @"\\192.0.2.1\C$", "Windows UNC changed");
Assert(ShareLinks.DolphinUrl("192.0.2.1", "Team #1", "name@realm", "p:@/ %;雪", "MY DOMAIN", false) ==
    "smb://MY%20DOMAIN;name%40realm:p%3A%40%2F%20%25%3B%E9%9B%AA@192.0.2.1/Team%20%231", "Dolphin credentials or share were changed");
Assert(ShareLinks.DolphinUrl("192.0.2.1", null, "user", "secret", "", false) == "smb://user:secret@192.0.2.1/", "server root lost credentials");
Assert(ShareLinks.DolphinUrl("192.0.2.1", "C$", "user", "", "DOMAIN", false) == "smb://DOMAIN;user@192.0.2.1/C%24", "empty password behavior changed");
Assert(ShareLinks.DolphinUrl("192.0.2.1", "share", "user", "sensitive-hash", "DOMAIN", true) == "smb://DOMAIN;user@192.0.2.1/share", "hash was sent to Dolphin as a password");
Assert(ShareLinks.DolphinUrl("192.0.2.1", "share", "", "secret", "DOMAIN", false) == ShareLinks.Url("192.0.2.1", "share"), "guest URL contains stray credentials");
foreach (string user in new[] { "user", @"EXAMPLE\user", "user@example.test", "user name 雪", "" })
foreach (string password in new[] { "", "fixture-password", " :/@%;\\雪 " })
foreach (string domain in new[] { "", "EXAMPLE" })
foreach (string? share in new string?[] { null, "Public", "Team #1 雪", "C$" })
foreach (bool useHash in new[] { false, true })
    Assert(ShareLinks.DolphinUrl("192.0.2.1", share, user, password, domain, useHash) ==
        OriginalSmbUrlFixture.Build("192.0.2.1", share, user, password, domain, useHash),
        "Authenticated Dolphin URL differs from the original version");
var dolphinStart = DolphinSmbLauncher.CreateStartInfo("/usr/bin/dolphin");
Assert(dolphinStart.FileName == "/usr/bin/dolphin" && !dolphinStart.UseShellExecute && dolphinStart.ArgumentList.Count == 2 &&
    dolphinStart.ArgumentList[0] == "--new-window" && dolphinStart.ArgumentList[1].StartsWith("file:///"), "Dolphin startup must open only a local folder");
foreach (string share in new[] { "..", "a/b", @"a\b", "a\n" })
{
    bool rejected = false;
    try { ShareLinks.Url("192.0.2.1", share); } catch (ArgumentException) { rejected = true; }
    Assert(rejected, "invalid share path accepted");
}
var log = new BoundedLog();
string logged = "";
for (int i = 0; i < 600; i++) logged = log.Append(i.ToString());
Assert(logged.StartsWith("100\n") && logged.EndsWith("599\n"), "log is not bounded");
Assert(log.RemovedLines == 1 && log.RemovedCharacters == "99\n".Length, "log rotation must report removed viewport content");
Assert(log.Append(new string('x', 10000)).Split('\n')[^2].Length <= BoundedLog.MaxLineCharacters + 1, "long log entry unbounded");
log.Clear();
Assert(log.RemovedLines == 0 && log.RemovedCharacters == 0, "clearing activity must reset its scroll adjustment");
Assert(log.Append("new") == "new\n", "cleared log returned old entries");
Assert(log.RemovedLines == 0 && log.RemovedCharacters == 0, "a log append without eviction must not move the reading position");
var nullable = System.Text.Json.JsonSerializer.Deserialize<AliveResult>("{\"Warnings\":null,\"TCPRefusedPorts\":null,\"Error\":null}")!;
nullable.Normalize();
Assert(!nullable.HasObservation && !nullable.HasProbeErrors && nullable.Diagnostics == "", "null optional discovery fields crash");
var nullableSmb = System.Text.Json.JsonSerializer.Deserialize<SmbResult>("{\"Shares\":[null],\"Warnings\":null}")!;
nullableSmb.Normalize();
Assert(nullableSmb.Shares.Length == 0 && nullableSmb.Diagnostics == "", "null share metadata crashes");
Assert(new ShareInfo { CanWrite = true }.Access == "W", "write-only permission falsely displayed as read/write");

foreach (var (type, label, browse) in new (uint, string, bool)[]
{
    (0, "Disk", true), (0x80000000, "Disk", true), (0x0e000000, "Disk", true), (0x40000000, "Disk", true),
    (1, "Printer", false), (0xc0000001, "Printer", false), (2, "Device", false), (3, "IPC", false), (0x7f, "Unknown", false)
})
{
    var resource = System.Text.Json.JsonSerializer.Deserialize<ShareInfo>($"{{\"Name\":\"Ordinary name\",\"ShareType\":{type}}}")!;
    Assert(resource.ShareType == type && resource.ResourceType == label && resource.CanOpenInFileManager == browse,
        "SMB resource type/flags lost or inferred from its name");
    Assert(resource.Access == (browse ? "✕" : label) && !resource.HasAccessError,
        "a non-file resource was presented as denied or incomplete file access");
    Assert(browse ? resource.OpenHint.Contains("Double-click") : resource.OpenHint.Contains("do not apply"),
        "a printer/device tooltip invites opening a file directory");
    var host = new SmbResult { EnumerationStatus = "Complete", Shares = new[] { resource } };
    Assert(!host.HasIncompleteChecks && host.SharesSummary.StartsWith("1 share (") &&
        (browse || host.ShareDetails.Contains($"[{label}]")), "resource was dropped or became a host error");
}

// The additive SMB schema must preserve old engine output and every discovered
// name, while distinguishing failed enumeration and unconfirmed access.
var legacySmb = System.Text.Json.JsonSerializer.Deserialize<SmbResult>(
    "{\"IP\":\"192.0.2.1\",\"Port445Open\":true,\"Status\":\"Authenticated\",\"Shares\":[{\"Name\":\"IPC$\"},{\"Name\":\"Restricted$\",\"CanRead\":true},{\"Name\":\"Team\",\"CanRead\":true,\"CanWrite\":true}]}")!;
legacySmb.Normalize();
Assert(legacySmb.EnumerationStatus == "" && !legacySmb.HasIncompleteChecks && !legacySmb.HasWarnings,
    "old engine output was incorrectly marked incomplete");
Assert(legacySmb.SharesSummary == "3 shares (2R/1W)" && legacySmb.ShareDetails == "IPC$[--]  Restricted$[R-]  Team[RW]",
    "legacy share presentation changed");
foreach (var (read, write, access) in new[] { (false, false, "?"), (true, false, "R?"), (false, true, "W?"), (true, true, "RW?") })
{
    var share = new ShareInfo { Name = "Restricted$", IP = "192.0.2.1", CanRead = read, CanWrite = write, AccessError = "Connection lost" };
    Assert(share.Access == access && share.CanRead == read && share.CanWrite == write,
        "inconclusive access changed a confirmed grant or claimed a denial");
    Assert(share.OpenHint.Contains("Connection lost") && share.OpenHint.Contains(@"\\192.0.2.1\Restricted$"),
        "the share tooltip lost its failure reason or original target");
}
Assert(!new ShareInfo { CanRead = true, AccessError = "Write check timed out" }.IsReadOnlyShare,
    "unknown write access was classified as read-only");
var dropFolder = System.Text.Json.JsonSerializer.Deserialize<SmbResult>("""
    {"EnumerationStatus":"Complete","Shares":[{"Name":"Incoming","ReadCheck":"Denied","WriteCheck":"Not checked",
      "AccessError":"Root listing denied. Write access was not checked."}]}
    """)!;
dropFolder.Normalize();
Assert(dropFolder.Shares[0].Access == "?" && dropFolder.Shares[0].OpenHint.Contains("not checked") &&
    dropFolder.HasAccessCheckErrors && dropFolder.ShareDetails.Contains("Incoming[-?]"),
    "a skipped write must remain unknown after an explicit root-listing denial");
Assert(System.Text.Json.JsonSerializer.Serialize(dropFolder).Contains("\"WriteCheck\":\"Not checked\""),
    "exported JSON lost the write-check outcome");
Assert(new SmbResult { Status = "Authenticated" }.SessionLabel == "Configured credentials" &&
    new SmbResult { Status = "Cancelled", CredentialSource = "Configured" }.SessionLabel == "Cancelled" &&
    new SmbResult { Status = "Guest Session" }.SessionLabel == "Guest Session",
    "the session label must preserve failures and describe only the credentials used");
Assert(new ShareInfo { CanRead = true }.IsReadOnlyShare && new ShareInfo().Access == "✕",
    "confirmed read-only and denied access changed");
foreach (var (status, expected) in new[]
{
    ("Complete", "None"), ("Failed", "Enumeration failed"), ("Partial", "Incomplete"), ("Not attempted", "Not enumerated"), ("", "None")
})
    Assert(new SmbResult { EnumerationStatus = status }.SharesSummary == expected,
        $"zero-share {status} enumeration was presented incorrectly");
var partialSmb = System.Text.Json.JsonSerializer.Deserialize<SmbResult>(
    "{\"IP\":\"192.0.2.2\",\"Port445Open\":true,\"EnumerationStatus\":\"Partial\",\"Shares\":[{\"Name\":\"First$\",\"CanRead\":true,\"AccessError\":\"Write check timed out\"},{\"Name\":\"Second\",\"AccessError\":\"Access check not completed\"}]}")!;
var selectedShare = partialSmb.Shares[0];
partialSmb.Normalize();
Assert(partialSmb.Shares.Length == 2 && ReferenceEquals(selectedShare, partialSmb.Shares[0]) &&
    partialSmb.Shares.All(s => s.IP == "192.0.2.2"), "normalization dropped names, share selection identity or host association");
Assert(partialSmb.HasIncompleteChecks && partialSmb.SharesSummary == "Incomplete · 2 shares (1R/0W)",
    "partial enumeration looks complete");
Assert(partialSmb.ShareDetails.Contains("First$[R?]") && partialSmb.ShareDetails.Contains("Write check timed out") &&
    partialSmb.ShareDetails.Contains("Second[??]"), "exportable share details lost access uncertainty or errors");
Assert(ExportSupport.Csv(partialSmb.EnumerationStatus, partialSmb.ShareDetails).Contains("Access check not completed"),
    "CSV lost per-share failure details");
var accessIncomplete = new SmbResult { EnumerationStatus = "Complete", Shares = partialSmb.Shares };
Assert(accessIncomplete.HasIncompleteChecks && accessIncomplete.SharesSummary.StartsWith("Access incomplete"),
    "complete name enumeration hid incomplete access checks");
var nullCompleteness = System.Text.Json.JsonSerializer.Deserialize<SmbResult>(
    "{\"EnumerationStatus\":null,\"Shares\":[null,{\"Name\":null,\"AccessError\":null}],\"Warnings\":[null,\"\"]}")!;
nullCompleteness.Normalize();
Assert(nullCompleteness.EnumerationStatus == "" && nullCompleteness.Shares.Length == 1 &&
    nullCompleteness.Shares[0].AccessError == "" && !nullCompleteness.HasIncompleteChecks && !nullCompleteness.HasWarnings,
    "null optional SMB completion metadata broke normalization");
var warningSmb = new SmbResult { EnumerationStatus = "Complete", Warnings = new[] { "Configured authentication failed; guest fallback was used" } };
Assert(warningSmb.HasWarnings && !warningSmb.HasIncompleteChecks, "guest fallback warnings became invisible or a fabricated check failure");
var failedSmb = new SmbResult { EnumerationStatus = "Failed", Error = "ListShares timed out" };
string smbSummary = SmbScanSummary.Format(new[] { legacySmb, partialSmb, failedSmb, warningSmb,
    new SmbResult { EnumerationStatus = "Not attempted" }, new SmbResult { EnumerationStatus = "Complete" } }, 7);
Assert(smbSummary.Contains("6 reachable (port 445), 7 unreachable") && smbSummary.Contains("5 shares") &&
    smbSummary.Contains("2 hosts with incomplete checks or errors") && smbSummary.Contains("1 host with warnings") &&
    smbSummary.Contains("1 host not enumerated"), "scan completion hid partial enumeration, warnings or skipped enumeration");
Assert(new SmbResult { EnumerationStatus = "Complete", Error = "Metadata failure" }.HasIncompleteChecks,
    "host errors disappeared when enumeration succeeded");
Assert(!SmbScanSummary.Format(new[] { legacySmb }, 0).Contains("incomplete"),
    "clean legacy scan was mislabeled incomplete");
var skippedSmb = new SmbResult { EnumerationStatus = "Not attempted" };
var warningAndError = new SmbResult { EnumerationStatus = "Failed", Warnings = new[] { "Fallback failed" } };
Assert(SmbScanSummary.FormatStatus(new[] { partialSmb, warningAndError, skippedSmb }, 7)
    .Contains("3 hosts to review"), "compact status loses skipped enumeration or counts an affected host twice");
Assert(!SmbScanSummary.FormatStatus(new[] { skippedSmb }, 0, portScanOnly: true).Contains("review") &&
    !SmbScanSummary.FormatStatus(new[] { skippedSmb }, 0, portScanOnly: true).Contains("shares"),
    "port-only status implies that share enumeration ran or failed");

Assert(accessIncomplete.Diagnostics.Contains("First$: Write check timed out") &&
    accessIncomplete.Diagnostics.Contains("Second: Access check not completed"),
    "per-share failures are absent from the Diagnostics column and Copy reason");
Assert(smbSummary.Contains("1 host with partial share lists") && smbSummary.Contains("1 host with failed share listing") &&
    smbSummary.Contains("1 host with incomplete access checks"), "summary conflates missing names with uncertain permissions");
var recoveredSmb = new SmbResult { IP = "192.0.2.10", Port445Open = true, EnumerationStatus = "Complete",
    ConnectionAttempts = 3, ConnectionErrors = new[] { "timeout", "connection refused" }, Shares = new[] { new ShareInfo { Name = "Public" } } };
Assert(recoveredSmb.ConnectionRecovered && !recoveredSmb.HasIncompleteChecks && !recoveredSmb.HasWarnings,
    "a recovered TCP connection is incorrectly presented as an incomplete scan");
Assert(SmbScanSummary.HostDiagnostic(recoveredSmb)!.Contains("TCP attempts=3") &&
    SmbScanSummary.HostDiagnostic(recoveredSmb)!.Contains("connection refused"), "recovery evidence is missing from Activity");
Assert(SmbScanSummary.Format(new[] { recoveredSmb }, 0).Contains("1 host recovered after TCP retry"),
    "summary hides recovered hosts");
Assert(SmbScanSummary.HostDiagnostic(legacySmb) == null, "clean SMB hosts flood the diagnostic log");
accessIncomplete.Port445Open = true;
Assert(SmbScanSummary.HostDiagnostic(accessIncomplete)!.Contains("Access checks incomplete; share list complete"),
    "completed enumeration became a missing-share claim");
var longDiagnostic = new SmbResult { Error = "error\r\ninjected\t" + new string('x', 5000) };
string diagnosticLine = SmbScanSummary.HostDiagnostic(longDiagnostic)!;
Assert(!diagnosticLine.Contains('\n') && !diagnosticLine.Contains('\r') && !diagnosticLine.Contains('\t') && diagnosticLine.Length < 2200,
    "diagnostic Activity line is unbounded or permits extra log lines");
var smbReportSource = new List<SmbResult> { recoveredSmb, new SmbResult { IP = "192.0.2.2", Error = "TCP failed", ConnectionAttempts = 3 } };
var smbReport = SmbEvidenceReport.Create(false, DateTimeOffset.UtcNow, new SmbReportSettings(50, 10, false, false, false), smbReportSource);
smbReportSource.Clear();
string smbReportJson = System.Text.Json.JsonSerializer.Serialize(smbReport);
using (var reportDocument = System.Text.Json.JsonDocument.Parse(smbReportJson))
{
    var root = reportDocument.RootElement;
    Assert(!root.GetProperty("Completed").GetBoolean() && root.GetProperty("Results").GetArrayLength() == 2,
        "report lost unreachable hosts or changed a partial scan into complete");
    Assert(root.GetProperty("Results")[0].GetProperty("IP").GetString() == "192.0.2.2", "evidence is not sorted by numeric IP");
    Assert(root.GetProperty("Config").GetProperty("Threads").GetInt32() == 50 && root.GetProperty("Config").GetProperty("Timeout").GetInt32() == 10,
        "report lost the scan's original settings");
    Assert(root.GetProperty("Config").EnumerateObject().Select(p => p.Name).Order().SequenceEqual(
        new[] { "Threads", "Timeout", "PortScanOnly", "EnableWMI", "EnableSNMP", "ResolveHostnames" }.Order()), "report settings include fields outside the credential-free allowlist");
}
Assert(smbReportJson.Contains("ConnectionErrors") && smbReportJson.Contains("Public") && smbReportJson.Contains("TCP failed"),
    "report lost connection or share evidence");

var addresses = new[] { "192.0.2.100", "192.0.2.9", "10.0.0.1", "192.0.2.10", "255.255.255.255" };
var sorted = new[] { "10.0.0.1", "192.0.2.9", "192.0.2.10", "192.0.2.100", "255.255.255.255" };
Assert(addresses.Select(ip => new AliveResult { IP = ip }).OrderBy(r => r.IPSortKey).Select(r => r.IP).SequenceEqual(sorted), "discovery IP order is lexical rather than numeric");
Assert(addresses.Select(ip => new SmbResult { IP = ip }).OrderBy(r => r.IPSortKey).Select(r => r.IP).SequenceEqual(sorted), "SMB IP order is lexical rather than numeric");
Assert(!System.Text.Json.JsonSerializer.Serialize(new AliveResult()).Contains("IPSortKey"), "presentation sort key leaked into evidence JSON");

var filtered = new ResultCollection<int>();
int resets = 0, incremental = 0;
filtered.CollectionChanged += (_, e) => { if (e.Action == System.Collections.Specialized.NotifyCollectionChangedAction.Reset) resets++; else incremental++; };
filtered.ReplaceAll(Enumerable.Range(0, 65536));
Assert(filtered.Count == 65536 && resets == 1 && incremental == 0, "large filter rebuild floods the grid with notifications");
filtered.ReplaceAll(filtered.Where(value => value % 2 == 0));
Assert(filtered.Count == 32768 && filtered[^1] == 65534 && resets == 2, "self-filtering lost results");
IEnumerable<int> BrokenSource() { yield return -1; throw new InvalidDataException("fixture"); }
try { filtered.ReplaceAll(BrokenSource()); } catch (InvalidDataException) { }
Assert(filtered.Count == 32768 && filtered[0] == 0 && resets == 2, "failed filter replaced valid results");
filtered.Add(65536);
Assert(incremental == 1, "incoming scan result lost incremental notification");

string cacheDirectory = Path.Combine(Path.GetTempPath(), "tknet-cache-test-" + Guid.NewGuid().ToString("N"));
try
{
    byte[] bytes = System.Text.Encoding.UTF8.GetBytes("engine fixture");
    string Publish() { using var source = new MemoryStream(bytes); return EngineCache.Publish(source, cacheDirectory, "engine"); }
    string path = Publish();
    Assert(File.ReadAllBytes(path).SequenceEqual(bytes), "engine cache has wrong bytes");
    File.WriteAllText(path, "truncated");
    Assert(Publish() == path && File.ReadAllBytes(path).SequenceEqual(bytes), "corrupt engine cache was trusted");
    // Finish a competing publication while the other publisher is still copying.
    var winnerTime = new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    foreach (bool repair in new[] { false, true })
    {
        File.Delete(path);
        if (repair) File.WriteAllText(path, "damaged engine");
        using var contender = new PublishDuringCopyStream(bytes, () =>
        {
            Publish();
            File.SetLastWriteTimeUtc(path, winnerTime);
        });
        Assert(EngineCache.Publish(contender, cacheDirectory, "engine") == path
            && File.GetLastWriteTimeUtc(path) == winnerTime && File.ReadAllBytes(path).SequenceEqual(bytes),
            "a concurrent publisher replaced an already verified engine");
    }
    File.Delete(path);
    var concurrentPaths = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(Publish)));
    Assert(concurrentPaths.All(p => p == path) && File.ReadAllBytes(path).SequenceEqual(bytes), "concurrent cache extraction corrupted engine");
    if (OperatingSystem.IsWindows())
    {
        File.WriteAllText(path, "damaged engine");
        using (File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bool lockedFileRejected = false;
            try { Publish(); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { lockedFileRejected = true; }
            Assert(lockedFileRejected, "a locked engine with the wrong digest was accepted");
        }
        Assert(Publish() == path && File.ReadAllBytes(path).SequenceEqual(bytes), "cache repair failed after the reader released the file");
    }
    File.Delete(path);
    Directory.CreateDirectory(path);
    bool invalidDestinationRejected = false;
    try { Publish(); }
    catch (Exception error) when (error is IOException or UnauthorizedAccessException) { invalidDestinationRejected = true; }
    Assert(invalidDestinationRejected && Directory.Exists(path), "an unusable cache destination was accepted");
    Directory.Delete(path);
    Assert(Directory.GetFiles(cacheDirectory, "*.tmp", SearchOption.AllDirectories).Length == 0, "temporary engine files leaked");
    string engineName = OperatingSystem.IsWindows() ? "tknet-engine.exe" : "tknet-engine";
    string parentEngine = Path.Combine(cacheDirectory, engineName);
    File.WriteAllBytes(parentEngine, bytes);
    string applicationDirectory = Directory.CreateDirectory(Path.Combine(cacheDirectory, "app")).FullName;
    Assert(EngineClient.FindAdjacentEngine(applicationDirectory) == null, "a parent-directory engine was selected");
    string adjacentEngine = Path.Combine(applicationDirectory, engineName);
    if (OperatingSystem.IsLinux())
    {
        File.CreateSymbolicLink(path, parentEngine);
        Assert(Publish() == path && new FileInfo(path).LinkTarget == null
            && File.ReadAllBytes(parentEngine).SequenceEqual(bytes), "a matching engine outside the cache was trusted through a link");
        File.CreateSymbolicLink(adjacentEngine, parentEngine);
        Assert(EngineClient.FindAdjacentEngine(applicationDirectory) == null, "an external engine symlink was selected");
        File.Delete(adjacentEngine);
    }
    File.WriteAllBytes(adjacentEngine, bytes);
    Assert(EngineClient.FindAdjacentEngine(applicationDirectory) == adjacentEngine, "an adjacent development engine was ignored");
}
finally { Directory.Delete(cacheDirectory, true); }

if (OperatingSystem.IsLinux())
{
    // Only synthetic subprocesses are used. No network access or embedded engine.
    string exe = Path.Combine(AppContext.BaseDirectory, "tknet-engine");
    void FakeEngine(string body)
    {
        File.WriteAllText(exe, "#!/bin/sh\nread request\n" + body + "\n");
        File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
    async Task<(string Outcome, int Results)> Run(string body)
    {
        FakeEngine(body);
        var client = new EngineClient();
        var completion = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        int results = 0;
        client.OnAliveResult += _ => results++;
        client.OnSmbResult += _ => results++;
        client.OnDone += () => completion.TrySetResult("done");
        client.OnFailed += failure => completion.TrySetResult(failure);
        Assert(client.StartScan(new { command = "alive" }), "failed to launch fake engine");
        string outcome = await completion.Task.WaitAsync(TimeSpan.FromSeconds(5));
        return (outcome, results);
    }
    try
    {
        var success = await Run("printf '%s\\n' '{\"type\":\"alive_result\",\"data\":{\"IP\":\"192.0.2.1\",\"IsAlive\":true,\"Status\":\"Confirmed\"}}' '{\"type\":\"done\",\"data\":null}'");
        Assert(success == ("done", 1), "completion overtook results");
        var failure = await Run("printf '%s\\n' '{\"type\":\"error\",\"data\":\"invalid config\"}' '{\"type\":\"done\",\"data\":null}'");
        Assert(failure.Outcome == "invalid config", "engine error became success");
        var crash = await Run("echo 'startup failure' >&2\nexit 7");
        Assert(crash.Outcome.Contains("code 7") && crash.Outcome.Contains("startup failure"), "crash/stderr lost");
        Assert((await Run("exit 0")).Outcome.Contains("without a completion"), "missing done became success");
        Assert((await Run("echo bad-json\nprintf '%s\\n' '{\"type\":\"done\"}'")).Outcome.Contains("Invalid engine output"), "malformed JSON became success");
        var arp = await Run("printf '%s\\n' '{\"type\":\"alive_result\",\"data\":{\"IP\":\"192.0.2.1\",\"IsAlive\":false,\"ARPObserved\":true,\"Status\":\"Unconfirmed (ARP only)\"}}' '{\"type\":\"done\"}'");
        Assert(arp == ("done", 1), "unconfirmed ARP observation disappeared");

        var unresolved = await Run("printf '%s\\n' '{\"type\":\"discovery_result\",\"data\":{\"IP\":\"192.0.2.1\",\"IsAlive\":false,\"Status\":\"No response\",\"Attempts\":2}}' '{\"type\":\"done\"}'");
        Assert(unresolved == ("done", 1), "completed nonresponding target was dropped");
        var incomplete = await Run("printf '%s\\n' '{\"type\":\"discovery_result\",\"data\":{\"IP\":\"192.0.2.1\",\"IsAlive\":false,\"Status\":\"Incomplete (probe errors)\",\"Warnings\":[\"ping unavailable\"]}}' '{\"type\":\"done\"}'");
        Assert(incomplete == ("done", 1), "probe failure result was dropped");

        foreach (string malformed in new[]
        {
            "{\"type\":\"unknown\"}",
            "{\"type\":\"progress\",\"data\":2}",
            "{\"type\":\"progress\",\"data\":\"bad\"}",
            "{\"type\":\"alive_result\",\"data\":null}",
            "{\"type\":\"smb_result\",\"data\":{\"IP\":\"bad\"}}"
        })
        {
            var invalid = await Run("printf '%s\\n' '" + malformed + "' '{\"type\":\"done\"}'");
            Assert(invalid.Outcome != "done", "malformed protocol event became success");
        }
        var nullSmb = await Run("printf '%s\\n' '{\"type\":\"smb_result\",\"data\":{\"IP\":\"192.0.2.1\",\"Shares\":null}}' '{\"type\":\"done\"}'");
        Assert(nullSmb == ("done", 1), "optional null SMB array broke the stream");
        Assert((await Run("printf '%s\\n' '{\"type\":\"done\"}' '{\"type\":\"log\",\"data\":\"late\"}'")).Outcome.Contains("after completion"), "late output accepted");

        FakeEngine("/bin/sleep 10\nprintf '%s\\n' '{\"type\":\"done\"}'");
        var concurrent = new EngineClient();
        var starts = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => concurrent.StartScan(new { command = "alive" }))));
        concurrent.Stop();
        Assert(starts.Count(started => started) == 1, "parallel callers launched multiple engines");
        var stopped = new EngineClient();
        int oldCompletions = 0;
        stopped.OnDone += () => Interlocked.Increment(ref oldCompletions);
        stopped.OnFailed += _ => Interlocked.Increment(ref oldCompletions);
        Assert(stopped.StartScan(new { command = "alive" }), "stop fixture failed to start");
        int generation = stopped.ScanId;
        Assert(!stopped.StartScan(new { command = "alive" }), "accepted concurrent scan");
        stopped.Stop();
        Assert(stopped.ScanId != generation, "stop did not invalidate queued UI events");
        await Task.Delay(150);
        Assert(oldCompletions == 0, "stopped scan emitted stale completion");
        FakeEngine("printf '%s\\n' '{\"type\":\"done\"}'");
        var restarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        stopped.OnDone += () => restarted.TrySetResult();
        Assert(stopped.StartScan(new { command = "alive" }), "restart failed");
        await restarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
    }
    finally { File.Delete(exe); }
}
Console.WriteLine($"PASS: {assertions} UI scope/engine assertions");
if (args.Contains("--dolphin-dbus")) await DolphinDbusChecks.RunAsync();
if (args.Contains("--dolphin-native")) await DolphinNativeCheck.RunAsync();

sealed class PublishDuringCopyStream(byte[] bytes, Action publish) : MemoryStream(bytes)
{
    public override void CopyTo(Stream destination, int bufferSize)
    {
        base.CopyTo(destination, bufferSize);
        publish();
    }
}
