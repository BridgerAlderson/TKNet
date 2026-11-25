using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace TKNetUI
{
    public class ProbeOutcome
    {
        public string Method { get; set; } = "";
        public int Attempt { get; set; }
        public string Outcome { get; set; } = "";
        public string Detail { get; set; } = "";
    }

    public class AliveResult
    {
        [JsonPropertyName("IP")] public string IP { get; set; } = "";
        [JsonIgnore] public uint IPSortKey => ResultSort.IPv4Key(IP);
        [JsonPropertyName("Hostname")] public string Hostname { get; set; } = "";
        [JsonPropertyName("IsAlive")] public bool IsAlive { get; set; }
        [JsonPropertyName("Status")] public string Status { get; set; } = "";
        [JsonPropertyName("ARPObserved")] public bool ARPObserved { get; set; }
        [JsonPropertyName("Warnings")] public string[] Warnings { get; set; } = Array.Empty<string>();
        [JsonPropertyName("Attempts")] public int Attempts { get; set; }
        [JsonPropertyName("CheckedAt")] public string CheckedAt { get; set; } = "";
        [JsonPropertyName("ProbeOutcomes")] public ProbeOutcome[] ProbeOutcomes { get; set; } = Array.Empty<ProbeOutcome>();
        [JsonPropertyName("TCPRefusedPorts")] public int[] TCPRefusedPorts { get; set; } = Array.Empty<int>();
        [JsonPropertyName("Error")] public string Error { get; set; } = "";
        [JsonIgnore] public bool HasObservation => IsAlive || ARPObserved || TCPRefusedPorts?.Length > 0;
        [JsonIgnore] public bool HasProbeErrors => !string.IsNullOrEmpty(Error) || Warnings?.Length > 0;
        [JsonIgnore] public string Diagnostics => string.Join("; ", (Warnings ?? Array.Empty<string>()).Prepend(Error).Where(s => !string.IsNullOrWhiteSpace(s)));
        [JsonPropertyName("MACAddress")] public string MACAddress { get; set; } = "";
        [JsonPropertyName("MACVendor")] public string MACVendor { get; set; } = "";
        [JsonPropertyName("ICMPLatency")] public string ICMPLatency { get; set; } = "";
        public bool ICMPAlive { get; set; }
        public bool NetBIOSAlive { get; set; }
        public bool ARPAlive { get; set; }
        [JsonPropertyName("TCPOpenPorts")] public int[] TCPOpenPorts { get; set; } = Array.Empty<int>();
        [JsonPropertyName("NetBIOSName")] public string NetBIOSName { get; set; } = "";
        [JsonPropertyName("DNSName")] public string DNSName { get; set; } = "";
        [JsonPropertyName("DetectionMethod")] public string DetectionMethod { get; set; } = "";

        public string OpenPortsList =>
            TCPOpenPorts?.Length > 0 ? string.Join(", ", TCPOpenPorts) : "";

        public void Normalize()
        {
            Hostname ??= ""; Status ??= ""; Error ??= ""; CheckedAt ??= "";
            MACAddress ??= ""; MACVendor ??= ""; ICMPLatency ??= "";
            NetBIOSName ??= ""; DNSName ??= ""; DetectionMethod ??= "";
            Warnings ??= Array.Empty<string>(); ProbeOutcomes ??= Array.Empty<ProbeOutcome>();
            TCPRefusedPorts ??= Array.Empty<int>(); TCPOpenPorts ??= Array.Empty<int>();
        }
    }

    public class ShareInfo
    {
        [JsonPropertyName("Name")] public string Name { get; set; } = "";
        [JsonPropertyName("ShareType")] public uint ShareType { get; set; }
        [JsonPropertyName("CanRead")] public bool CanRead { get; set; }
        [JsonPropertyName("CanWrite")] public bool CanWrite { get; set; }
        [JsonPropertyName("ReadCheck")] public string? ReadCheck { get; set; }
        [JsonPropertyName("WriteCheck")] public string? WriteCheck { get; set; }
        [JsonPropertyName("AccessError")] public string AccessError { get; set; } = "";

        // Populated client-side from the parent SmbResult so a share chip can build
        // its own smb:// URL when double-clicked. Not part of the engine JSON.
        [JsonIgnore] public string IP { get; set; } = "";

        // Read-only = mountable and listable, but no write access.
        [JsonIgnore] public bool CanOpenInFileManager => (ShareType & 0xff) == 0;
        [JsonIgnore] public string ResourceType => (ShareType & 0xff) switch
        {
            0 => "Disk", 1 => "Printer", 2 => "Device", 3 => "IPC", _ => "Unknown"
        };
        [JsonIgnore] public bool IsReadOnlyShare => CanOpenInFileManager && CanRead && !CanWrite && !HasAccessError;
        [JsonIgnore] public bool HasAccessError => !string.IsNullOrWhiteSpace(AccessError);

        // A failed check is inconclusive; keep any confirmed access without
        // presenting an untested permission as denied or granted.
        [JsonIgnore] public string Access
        {
            get
            {
                if (!CanOpenInFileManager) return ResourceType;
                string confirmed = CanRead && CanWrite ? "RW" : CanWrite ? "W" : CanRead ? "R" : "";
                return HasAccessError ? confirmed + "?" : confirmed.Length > 0 ? confirmed : "✕";
            }
        }
        [JsonIgnore] public string ChipText => $"{Name}  {Access}";
        internal string PermissionMarks => Mark(ReadCheck, CanRead, "R") + Mark(WriteCheck, CanWrite, "W");
        private string Mark(string? check, bool granted, string letter) => check switch
        {
            "Granted" => letter, "Denied" => "-", "Not checked" or "Inconclusive" => "?",
            _ => granted ? letter : HasAccessError ? "?" : "-" // Older reports carry only booleans and diagnostics.
        };
        [JsonIgnore] public string OpenHint => !CanOpenInFileManager
            ? $"{ResourceType} share \\\\{IP}\\{Name} (server type 0x{ShareType:x8}). File read/write checks do not apply."
            : $"Double-click or press Enter to open \\\\{IP}\\{Name} in the file manager" +
            (HasAccessError ? $"\nAccess checks incomplete: {AccessError}" : "");
    }

    public class SmbResult
    {
        [JsonPropertyName("IP")] public string IP { get; set; } = "";
        [JsonIgnore] public uint IPSortKey => ResultSort.IPv4Key(IP);
        [JsonPropertyName("Hostname")] public string Hostname { get; set; } = "";
        [JsonPropertyName("Port445Open")] public bool Port445Open { get; set; }
        [JsonPropertyName("ConnectionAttempts")] public int ConnectionAttempts { get; set; }
        [JsonPropertyName("ConnectionErrors")] public string[] ConnectionErrors { get; set; } = Array.Empty<string>();
        [JsonPropertyName("ConnectionRecoveryAttempted")] public bool ConnectionRecoveryAttempted { get; set; }
        [JsonPropertyName("Status")] public string Status { get; set; } = "";
        [JsonPropertyName("CredentialSource")] public string? CredentialSource { get; set; }
        // Keep the original wire status. The server may map supplied credentials to Guest.
        [JsonIgnore] public string SessionLabel => Status == "Authenticated" ? "Configured credentials" : Status;
        [JsonPropertyName("EnumerationStatus")] public string EnumerationStatus { get; set; } = "";
        [JsonPropertyName("SMBVersion")] public string SMBVersion { get; set; } = "";
        [JsonPropertyName("OSVersion")] public string OSVersion { get; set; } = "";
        [JsonPropertyName("IsAdmin")] public bool IsAdmin { get; set; }
        [JsonPropertyName("Error")] public string Error { get; set; } = "";
        [JsonPropertyName("WMIInfo")] public string WMIInfo { get; set; } = "";
        [JsonPropertyName("SNMPInfo")] public string SNMPInfo { get; set; } = "";
        [JsonPropertyName("Shares")] public ShareInfo[] Shares { get; set; } = Array.Empty<ShareInfo>();
        [JsonPropertyName("Warnings")] public string[] Warnings { get; set; } = Array.Empty<string>();
        [JsonIgnore] public string Diagnostics => string.Join("; ", (Warnings ?? Array.Empty<string>()).Prepend(Error)
            .Concat((Shares ?? Array.Empty<ShareInfo>()).Where(s => s?.HasAccessError == true).Select(s => $"{s.Name}: {s.AccessError}"))
            .Where(s => !string.IsNullOrWhiteSpace(s)));
        [JsonIgnore] public bool HasAccessCheckErrors => Shares?.Any(s => s?.HasAccessError == true) == true;
        [JsonIgnore] public bool ConnectionRecovered => Port445Open && ConnectionAttempts > 1;
        [JsonIgnore] public bool HasIncompleteChecks => !string.IsNullOrWhiteSpace(Error) ||
            EnumerationStatus is "Partial" or "Failed" || (Shares?.Any(s => s?.HasAccessError == true) ?? false);
        [JsonIgnore] public bool HasWarnings => Warnings?.Any(s => !string.IsNullOrWhiteSpace(s)) == true;

        public void Normalize()
        {
            Hostname ??= ""; Status ??= ""; EnumerationStatus ??= ""; SMBVersion ??= ""; OSVersion ??= "";
            Error ??= ""; WMIInfo ??= ""; SNMPInfo ??= ""; Warnings ??= Array.Empty<string>();
            ConnectionErrors ??= Array.Empty<string>();
            Shares = (Shares ?? Array.Empty<ShareInfo>()).Where(s => s != null).ToArray();
            foreach (var share in Shares) { share.Name ??= ""; share.AccessError ??= ""; share.IP = IP; }
        }

        public string SharesSummary
        {
            get
            {
                if (Shares == null || Shares.Length == 0)
                    return EnumerationStatus switch
                    {
                        "Failed" => "Enumeration failed",
                        "Partial" => "Incomplete",
                        "Not attempted" => "Not enumerated",
                        _ => "None"
                    };
                int read = 0, write = 0;
                foreach (var s in Shares) { if (s.CanRead) read++; if (s.CanWrite) write++; }
                string incomplete = EnumerationStatus is "Partial" or "Failed" ? "Incomplete · "
                    : Shares.Any(s => s.HasAccessError) ? "Access incomplete · " : "";
                return $"{incomplete}{Shares.Length} {(Shares.Length == 1 ? "share" : "shares")} ({read}R/{write}W)";
            }
        }

        public string ShareDetails =>
            Shares?.Length > 0
                ? string.Join("  ", Shares.Select(s =>
                    (!s.CanOpenInFileManager ? $"{s.Name}[{s.ResourceType}]" :
                    $"{s.Name}[{s.PermissionMarks}]") +
                    (s.HasAccessError ? $" (Access incomplete: {s.AccessError})" : "")))
                : "";
    }

    // Explicit allowlist: the scan request (credentials/community) is never serialized.
    public sealed record SmbReportSettings(int Threads, int Timeout, bool PortScanOnly, bool EnableWMI, bool EnableSNMP, bool ResolveHostnames = false);

    public sealed record SmbEvidenceReport(int SchemaVersion, bool Completed, DateTimeOffset StartedAt,
        DateTimeOffset ExportedAt, SmbReportSettings Config, SmbResult[] Results)
    {
        public static SmbEvidenceReport Create(bool completed, DateTimeOffset startedAt,
            SmbReportSettings settings, IEnumerable<SmbResult> results) =>
            new(1, completed, startedAt, DateTimeOffset.UtcNow, settings, results.OrderBy(r => r.IPSortKey).ToArray());
    }

    internal static class SmbScanSummary
    {
        public static string FormatStatus(IReadOnlyCollection<SmbResult> reachable, int unreachable, bool portScanOnly = false)
        {
            long shares = reachable.Sum(r => (long)(r.Shares?.Length ?? 0));
            string status = portScanOnly ? "SMB port check finished: "
                : $"SMB finished: {shares} {(shares == 1 ? "share" : "shares")} · ";
            status += $"{reachable.Count} reachable · {unreachable} unreachable";
            int review = reachable.Count(r => r.HasIncompleteChecks || r.HasWarnings ||
                (!portScanOnly && r.EnumerationStatus == "Not attempted"));
            if (review > 0) status += $" · {review} {(review == 1 ? "host" : "hosts")} to review";
            return status;
        }

        public static string Format(IReadOnlyCollection<SmbResult> reachable, int unreachable)
        {
            long shares = reachable.Sum(r => (long)(r.Shares?.Length ?? 0));
            var parts = new List<string>
            {
                $"SMB scan finished — {reachable.Count} reachable (port 445), {unreachable} unreachable",
                $"{shares} {(shares == 1 ? "share" : "shares")}"
            };
            int incomplete = reachable.Count(r => r.HasIncompleteChecks);
            int warnings = reachable.Count(r => r.HasWarnings);
            int notEnumerated = reachable.Count(r => r.EnumerationStatus == "Not attempted");
            int partial = reachable.Count(r => r.EnumerationStatus == "Partial");
            int failed = reachable.Count(r => r.EnumerationStatus == "Failed");
            int access = reachable.Count(r => r.HasAccessCheckErrors);
            int recovered = reachable.Count(r => r.ConnectionRecovered);
            static string Hosts(int count) => $"{count} {(count == 1 ? "host" : "hosts")}";
            if (incomplete > 0) parts.Add($"{Hosts(incomplete)} with incomplete checks or errors");
            if (warnings > 0) parts.Add($"{Hosts(warnings)} with warnings");
            if (notEnumerated > 0) parts.Add($"{Hosts(notEnumerated)} not enumerated");
            if (partial > 0) parts.Add($"{Hosts(partial)} with partial share lists");
            if (failed > 0) parts.Add($"{Hosts(failed)} with failed share listing");
            if (access > 0) parts.Add($"{Hosts(access)} with incomplete access checks (known names retained)");
            if (recovered > 0) parts.Add($"{Hosts(recovered)} recovered after TCP retry");
            return string.Join("; ", parts) + ".";
        }

        // Full data remains available in the JSON evidence report.
        public static string? HostDiagnostic(SmbResult result)
        {
            if (!result.HasIncompleteChecks && !result.HasWarnings && !result.ConnectionRecovered && result.Port445Open)
                return null;
            string phase = !result.Port445Open ? "TCP connection failed"
                : result.EnumerationStatus == "Not attempted" ? "SMB session / enumeration not started"
                : result.EnumerationStatus is "Partial" or "Failed" ? "Share listing " + result.EnumerationStatus.ToLowerInvariant()
                : result.HasAccessCheckErrors ? "Access checks incomplete; share list " + result.EnumerationStatus.ToLowerInvariant()
                : result.HasWarnings ? "Warning" : "TCP connection recovered";
            string detail = result.Diagnostics;
            if (result.ConnectionErrors.Length > 0)
                detail = $"TCP attempts={result.ConnectionAttempts}, previous failures={string.Join(", ", result.ConnectionErrors)}; " + detail;
            if (result.ConnectionRecoveryAttempted)
                detail = "Final TCP verification performed after the initial sweep; " + detail;
            detail = detail.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
            if (detail.Length > 2000) detail = detail[..2000] + "… (full details in SMB JSON report)";
            return $"SMB {result.IP} — {phase}; {result.Shares.Length} known {(result.Shares.Length == 1 ? "share" : "shares")}. {detail}".TrimEnd();
        }
    }

}
