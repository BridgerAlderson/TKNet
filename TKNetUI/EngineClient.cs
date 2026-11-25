using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace TKNetUI
{
    public class EngineEvent
    {
        [JsonPropertyName("type")] public string Type { get; set; } = "";
        [JsonPropertyName("data")] public JsonElement Data { get; set; }
    }

    public class EngineClient
    {
        private readonly object _gate = new();
        private Process? _process;
        private int _scanId;
        public int ScanId { get { lock (_gate) return _scanId; } }

        public event Action<string>? OnLog;
        public event Action<double>? OnProgress;
        public event Action<AliveResult>? OnAliveResult;
        public event Action<SmbResult>? OnSmbResult;
        public event Action? OnDone;
        public event Action<string>? OnFailed;

        public bool StartScan(object config)
        {
            lock (_gate)
            {
                if (_process != null) { OnLog?.Invoke("A scan is already running."); return false; }
                Process? process = null;
                try
                {
                    string? exePath = FindEngineExe();
                    if (exePath == null) throw new FileNotFoundException("tknet-engine not found in embedded resources or local directory.");
                    string json = JsonSerializer.Serialize(config);
                    process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = exePath,
                            Arguments = "--headless",
                            RedirectStandardInput = true,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            StandardInputEncoding = new UTF8Encoding(false),
                            StandardOutputEncoding = Encoding.UTF8,
                            StandardErrorEncoding = Encoding.UTF8,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };
                    process.Start();
                    int scanId;
                    _process = process;
                    scanId = ++_scanId;
                    // Capture this process, never read a mutable _process from the task.
                    _ = ReadScanAsync(process, scanId, json);
                    return true;
                }
                catch (Exception ex)
                {
                    process?.Dispose();
                    OnFailed?.Invoke($"Engine startup failed: {ex.Message}");
                    return false;
                }
            }
        }

        private async Task ReadScanAsync(Process process, int scanId, string json)
        {
            bool done = false;
            string? failure = null;
            // Drain stderr concurrently so diagnostics cannot fill a pipe and hang the engine.
            var stderr = ReadDiagnosticsAsync(process.StandardError);
            try
            {
                await process.StandardInput.WriteLineAsync(json);
                process.StandardInput.Close();
                while (await process.StandardOutput.ReadLineAsync() is string line)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    EngineEvent evt;
                    try { evt = JsonSerializer.Deserialize<EngineEvent>(line) ?? throw new JsonException("Empty event"); }
                    catch (JsonException ex) { failure ??= $"Invalid engine output: {ex.Message}"; continue; }
                    if (done) { failure ??= "Engine sent output after completion."; continue; }
                    if (evt.Type == "done") { done = true; continue; }
                    if (evt.Type == "error")
                    {
                        failure ??= evt.Data.ValueKind == JsonValueKind.String ? evt.Data.GetString() : "Engine error";
                        continue;
                    }
                    lock (_gate)
                    {
                        if (scanId != _scanId) continue;
                        HandleEvent(evt);
                    }
                }
                await process.WaitForExitAsync();
                string diagnostics = await stderr;
                if (process.ExitCode != 0) failure ??= $"Engine exited with code {process.ExitCode}. {diagnostics}".Trim();
                if (!done) failure ??= $"Engine exited without a completion event. {diagnostics}".Trim();
            }
            catch (Exception ex)
            {
                failure ??= $"Engine communication failed: {ex.Message}";
            }
            finally
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
                // Always observe the stderr reader, including Stop()/pipe failures.
                try { await stderr; } catch { }
                lock (_gate)
                {
                    if (scanId == _scanId)
                    {
                        _process = null;
                        if (failure != null) OnFailed?.Invoke(failure);
                        else OnDone?.Invoke();
                    }
                }
                process.Dispose();
            }
        }

        private static async Task<string> ReadDiagnosticsAsync(StreamReader reader)
        {
            var text = new System.Text.StringBuilder();
            char[] buffer = new char[1024];
            int count;
            while ((count = await reader.ReadAsync(buffer, 0, buffer.Length)) > 0)
                if (text.Length < 8192) text.Append(buffer, 0, Math.Min(count, 8192 - text.Length));
            return text.ToString().Trim();
        }

        private void HandleEvent(EngineEvent evt)
        {
            switch (evt.Type)
            {
                case "log":
                    if (evt.Data.ValueKind != JsonValueKind.String) throw new JsonException("Log event requires text.");
                    OnLog?.Invoke(evt.Data.GetString() ?? "");
                    break;
                case "progress":
                    if (evt.Data.ValueKind != JsonValueKind.Number || !evt.Data.TryGetDouble(out double progress) ||
                        !double.IsFinite(progress) || progress < 0 || progress > 1)
                        throw new JsonException("Progress must be a number between zero and one.");
                    OnProgress?.Invoke(progress);
                    break;
                case "alive_result":
                case "discovery_result":
                    var alive = evt.Data.Deserialize<AliveResult>() ?? throw new JsonException("Missing discovery result.");
                    ValidateResultIP(alive.IP);
                    alive.Normalize();
                    OnAliveResult?.Invoke(alive);
                    break;
                case "smb_result":
                    var smb = evt.Data.Deserialize<SmbResult>() ?? throw new JsonException("Missing SMB result.");
                    ValidateResultIP(smb.IP);
                    smb.Normalize();
                    OnSmbResult?.Invoke(smb);
                    break;
                default:
                    throw new JsonException("Unknown engine event type.");
            }
        }

        private static void ValidateResultIP(string ip)
        {
            if (!System.Net.IPAddress.TryParse(ip, out var address) ||
                address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || address.ToString() != ip)
                throw new JsonException("Result requires a canonical IPv4 address.");
        }

        public void Stop()
        {
            Process? process;
            lock (_gate) { ++_scanId; process = _process; _process = null; }
            // The reader owns disposal. Stop also terminates Linux ping/arping children.
            try { if (process != null && !process.HasExited) process.Kill(entireProcessTree: true); } catch { }
        }

        private string? FindEngineExe()
        {
            string? extracted = ExtractEngine();
            if (!string.IsNullOrEmpty(extracted) && File.Exists(extracted))
                return extracted;

            return FindAdjacentEngine(AppContext.BaseDirectory);
        }

        internal static string? FindAdjacentEngine(string applicationDirectory)
        {
            string name = OperatingSystem.IsWindows() ? "tknet-engine.exe" : "tknet-engine";
            var adjacent = new FileInfo(Path.Combine(applicationDirectory, name));
            return adjacent.Exists && !adjacent.Attributes.HasFlag(FileAttributes.ReparsePoint) ? adjacent.FullName : null;
        }

        private string? ExtractEngine()
        {
            bool isWindows = OperatingSystem.IsWindows();
            string exeName = isWindows ? "tknet-engine.exe" : "tknet-engine";
            var assembly = System.Reflection.Assembly.GetExecutingAssembly();
            string? resourceName = assembly.GetManifestResourceNames().FirstOrDefault(
                r => r.EndsWith("." + exeName, StringComparison.OrdinalIgnoreCase));
            if (resourceName == null) return null;

            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null) return null;
            string cache = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TKNet", "Engine");
            return EngineCache.Publish(stream, cache, exeName);
        }
    }
}
