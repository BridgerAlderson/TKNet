using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using TKNetUI;
using Tmds.DBus.Protocol;

// Run explicitly with --dolphin-dbus. All services live on a private bus; these
// tests never contact the user's desktop, a real Dolphin, or an SMB server.
internal static class DolphinDbusChecks
{
    private static string Digest(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    public static async Task RunAsync()
    {
        using var daemon = Process.Start(new ProcessStartInfo
        {
            FileName = "dbus-daemon", UseShellExecute = false, RedirectStandardOutput = true,
            ArgumentList = { "--session", "--nofork", "--nopidfile", "--print-address=1" }
        })!;
        int checks = 0;
        void Check(bool ok, string message) { if (!ok) throw new Exception(message); checks++; }
        try
        {
            string address = await daemon.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5)) ?? throw new Exception("No private bus address");
            string url = ShareLinks.DolphinUrl("192.0.2.1", "Team #1", "name@realm", "test:/@% secret", "DOMAIN", false);
            string fixture = Environment.ProcessPath ?? throw new Exception("Missing test executable");
            using (var server = new Connection(address))
            {
                await server.ConnectAsync();
                var window = new FakeWindow();
                server.AddMethodHandler(window);
                await OwnNameAsync(server);
                var otherImage = new DolphinSmbLauncher(address, _ => null, "/usr/bin/true");
                try { await otherImage.OpenAsync(url); throw new Exception("Unverified window accepted"); }
                catch (InvalidOperationException ex) when (ex.Message == "Dolphin could not start.") { }
                Check(window.OpenCalls == 0, "A different executable received the URL");
                var launcher = new DolphinSmbLauncher(address, _ => throw new Exception("Existing window was ignored"), fixture);
                await launcher.OpenAsync(url);
                Check(window.Urls.TryDequeue(out var received) && received == url, "D-Bus handoff changed credentials or target");
                Check(window.OpenDestination == server.UniqueName, "URL was not addressed to the verified unique connection");
                Check(!window.SplitView, "D-Bus boolean argument was corrupted");
                await Task.WhenAll(launcher.OpenAsync(url), launcher.OpenAsync(url));
                Check(window.Urls.Count == 2, "Concurrent open requests were lost");
                window.Reject = true;
                int opensBeforeRejection = window.OpenCalls;
                bool rejected = false;
                try { await launcher.OpenAsync(url); } catch (DBusException) { rejected = true; }
                Check(rejected, "Dolphin error reported as successful delivery");
                Check(window.OpenCalls == opensBeforeRejection + 1, "Dolphin error triggered an automatic retry");
                int manualRejections = 0;
                for (int attempt = 0; attempt < 32; attempt++)
                {
                    try { await launcher.OpenAsync(url); } catch (DBusException) { manualRejections++; }
                }
                Check(manualRejections == 32 && window.OpenCalls == opensBeforeRejection + 33,
                    "Repeated manual errors caused extra requests or became success");
                using var canceled = new CancellationTokenSource();
                canceled.Cancel();
                bool stopped = false;
                try { await launcher.OpenAsync(url, canceled.Token); } catch (OperationCanceledException) { stopped = true; }
                Check(stopped, "Canceled request was sent to Dolphin");
            }

            // No window remains. Simulate Dolphin's startup and service registration
            // in a separate process, including its actual PID-based service name.
            Task<string>? output = null;
            var coldLauncher = new DolphinSmbLauncher(address, info =>
            {
                Check(info.FileName == fixture && info.ArgumentList.Count == 2 &&
                    info.ArgumentList[0] == "--new-window" && info.ArgumentList[1].StartsWith("file:///"), "Cold start included a network URL or credential");
                var fake = new ProcessStartInfo { FileName = fixture, UseShellExecute = false, RedirectStandardOutput = true };
                if (Path.GetFileName(fixture) == "dotnet") fake.ArgumentList.Add(typeof(DolphinDbusChecks).Assembly.Location);
                fake.ArgumentList.Add("--fake-dolphin");
                fake.ArgumentList.Add(address);
                var process = Process.Start(fake)!;
                output = process.StandardOutput.ReadToEndAsync();
                return process;
            }, fixture);
            await coldLauncher.OpenAsync(url);
            Check((await output!.WaitAsync(TimeSpan.FromSeconds(5))).Trim() == Digest(url), "Cold window did not receive the same authenticated URL");
            Console.WriteLine($"PASS: {checks} isolated Dolphin D-Bus checks (no SMB access)");
        }
        finally { if (!daemon.HasExited) daemon.Kill(); await daemon.WaitForExitAsync(); }
    }

    public static async Task RunFakeAsync(string address)
    {
        using var server = new Connection(address);
        await server.ConnectAsync();
        var window = new FakeWindow();
        await OwnNameAsync(server);
        // The bus name may exist before the window object is ready.
        await Task.Delay(250);
        server.AddMethodHandler(window);
        string value = await window.FirstUrl.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Console.WriteLine(Digest(value));
        await Task.Delay(300);
    }

    private static Task<uint> OwnNameAsync(Connection connection)
    {
        using var writer = connection.GetMessageWriter();
        writer.WriteMethodCallHeader(destination: "org.freedesktop.DBus", path: "/org/freedesktop/DBus",
            @interface: "org.freedesktop.DBus", member: "RequestName", signature: "su");
        writer.WriteString("org.kde.dolphin-" + Environment.ProcessId);
        writer.WriteUInt32(4); // Do not queue behind another owner.
        return connection.CallMethodAsync(writer.CreateMessage(), (message, _) => message.GetBodyReader().ReadUInt32());
    }

    private sealed class FakeWindow : IMethodHandler
    {
        public string Path => DolphinSmbLauncher.WindowPath;
        public ConcurrentQueue<string> Urls { get; } = new();
        public TaskCompletionSource<string> FirstUrl { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool SplitView, Reject;
        public string? OpenDestination;
        public int OpenCalls;
        public bool RunMethodHandlerSynchronously(Message message) => true;
        public ValueTask HandleMethodAsync(MethodContext context)
        {
            var request = context.Request;
            if (request.InterfaceAsString != DolphinSmbLauncher.WindowInterface) return default;
            switch ((request.MemberAsString, request.SignatureAsString))
            {
                case ("isActiveWindow", null or ""):
                    using (var writer = context.CreateReplyWriter("b"))
                    {
                        writer.WriteBool(true);
                        context.Reply(writer.CreateMessage());
                    }
                    break;
                case ("openDirectories", "asb"):
                    Interlocked.Increment(ref OpenCalls);
                    OpenDestination = request.DestinationAsString;
                    var reader = request.GetBodyReader();
                    string[] urls = reader.ReadArrayOfString();
                    SplitView = reader.ReadBool();
                    if (Reject) { context.ReplyError("org.freedesktop.DBus.Error.Failed", "Synthetic rejection"); break; }
                    if (urls.Length != 1) throw new Exception("Unexpected URL count");
                    Urls.Enqueue(urls[0]);
                    using (var writer = context.CreateReplyWriter(null)) context.Reply(writer.CreateMessage());
                    FirstUrl.TrySetResult(urls[0]);
                    break;
                case ("activateWindow", "s"):
                    using (var writer = context.CreateReplyWriter(null)) context.Reply(writer.CreateMessage());
                    break;
            }
            return default;
        }
    }
}
