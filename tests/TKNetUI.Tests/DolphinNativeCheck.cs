using System.Diagnostics;
using TKNetUI;
using Tmds.DBus.Protocol;

internal static class DolphinNativeCheck
{
    // Explicit opt-in. Uses the installed Dolphin with an offscreen Qt platform,
    // disposable XDG directories and a private bus. Opens only a local fixture.
    public static async Task RunAsync()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("This optional check requires Linux and Dolphin.");
        // KIO socket paths must stay below the Unix-domain socket path limit.
        string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "tkdn-" + Guid.NewGuid().ToString("N")[..12]);
        Directory.CreateDirectory(directory);
        var env = new Dictionary<string, string>
        {
            ["QT_QPA_PLATFORM"] = "offscreen", ["DISPLAY"] = "", ["WAYLAND_DISPLAY"] = "",
            ["NO_AT_BRIDGE"] = "1", ["QT_ACCESSIBILITY"] = "0"
        };
        foreach (string key in new[] { "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR" })
        {
            string path = System.IO.Path.Combine(directory, key == "XDG_RUNTIME_DIR" ? "r" : key);
            Directory.CreateDirectory(path);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            env[key] = path;
        }
        // No desktop service activation: the fixture must not launch portals,
        // wallets, FUSE mounts or accessibility services from the user's session.
        string busConfig = System.IO.Path.Combine(directory, "bus.conf");
        File.WriteAllText(busConfig, """
            <busconfig>
              <type>session</type><listen>unix:tmpdir=/tmp</listen><auth>EXTERNAL</auth>
              <policy context="default">
                <allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/>
              </policy>
            </busconfig>
            """);
        var daemonInfo = new ProcessStartInfo
        {
            FileName = "dbus-daemon", UseShellExecute = false, RedirectStandardOutput = true,
            ArgumentList = { "--config-file=" + busConfig, "--nofork", "--nopidfile", "--print-address=1" }
        };
        foreach (var (key, value) in env) daemonInfo.Environment[key] = value;
        using var daemon = Process.Start(daemonInfo)!;
        Process? dolphin = null;
        try
        {
            string address = await daemon.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5)) ?? throw new Exception("No private bus address");
            var launcher = new DolphinSmbLauncher(address, info =>
            {
                foreach (var (key, value) in env) info.Environment[key] = value;
                info.Environment["DBUS_SESSION_BUS_ADDRESS"] = address;
                // Avoid restoring or examining any real user folder in this test.
                info.ArgumentList[1] = new Uri(directory + "/").AbsoluteUri;
                var process = Process.Start(info)!;
                // Launcher disposes its process handle, so retain a separate one for cleanup.
                dolphin = Process.GetProcessById(process.Id);
                return process;
            });
            string folder = System.IO.Path.Combine(directory, "Team #1 雪");
            Directory.CreateDirectory(folder);
            string url = new Uri(folder + "/").AbsoluteUri;
            await launcher.OpenAsync(url);
            using var connection = new Connection(address);
            await connection.ConnectAsync();
            if (!await IsOpenAsync(connection, "org.kde.dolphin-" + dolphin!.Id, url).WaitAsync(TimeSpan.FromSeconds(3)))
                throw new Exception("Dolphin did not open the local fixture");
            await launcher.OpenAsync(url); // Existing-window path uses the same native interface.
            Console.WriteLine("PASS: installed Dolphin cold start, local folder handoff and existing-window reuse (no SMB authentication)");
        }
        finally
        {
            if (dolphin != null)
            {
                if (!dolphin.HasExited) dolphin.Kill(entireProcessTree: true);
                await dolphin.WaitForExitAsync();
                dolphin.Dispose();
            }
            if (!daemon.HasExited) daemon.Kill(entireProcessTree: true);
            await daemon.WaitForExitAsync();
            Directory.Delete(directory, true);
        }
    }

    private static Task<bool> IsOpenAsync(Connection connection, string service, string url)
    {
        using var writer = connection.GetMessageWriter();
        writer.WriteMethodCallHeader(destination: service, path: DolphinSmbLauncher.WindowPath,
            @interface: DolphinSmbLauncher.WindowInterface, member: "isUrlOpen", signature: "s");
        writer.WriteString(url);
        return connection.CallMethodAsync(writer.CreateMessage(), (message, _) => message.GetBodyReader().ReadBool());
    }
}
