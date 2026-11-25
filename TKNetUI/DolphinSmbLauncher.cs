using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Tmds.DBus.Protocol;

namespace TKNetUI;

// Use Dolphin's window interface directly: FileManager1.ShowFolders can launch
// another process with the URL on its command line when no window exists.
internal sealed class DolphinSmbLauncher
{
    internal const string WindowPath = "/dolphin/Dolphin_1";
    internal const string WindowInterface = "org.kde.dolphin.MainWindow";
    private const string Bus = "org.freedesktop.DBus";
    private const string BusPath = "/org/freedesktop/DBus";
    private const string ServicePrefix = "org.kde.dolphin-";
    private static readonly string[] SystemExecutables =
        { "/usr/bin/dolphin", "/usr/local/bin/dolphin", "/bin/dolphin", "/run/current-system/sw/bin/dolphin" };
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string? _sessionAddress;
    private readonly Func<ProcessStartInfo, Process?> _start;
    private readonly string[] _executables;

    internal DolphinSmbLauncher(string? sessionAddress = null, Func<ProcessStartInfo, Process?>? start = null,
        string? fixtureExecutable = null)
    {
        _sessionAddress = sessionAddress;
        _start = start ?? Process.Start;
        _executables = fixtureExecutable == null ? SystemExecutables : new[] { fixtureExecutable };
    }

    public async Task OpenAsync(string url, CancellationToken cancellation = default)
    {
        await _gate.WaitAsync(cancellation);
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            deadline.CancelAfter(TimeSpan.FromSeconds(15));
            var token = deadline.Token;
            using var connection = new Connection(_sessionAddress ?? Address.Session ?? throw new InvalidOperationException("Desktop session bus is unavailable."));
            await connection.ConnectAsync().AsTask().WaitAsync(token);
            string? service = await FindWindowAsync(connection, token);
            if (service == null)
            {
                // Start with a local folder. The secret URL is sent only after
                // Dolphin has registered its window on the session bus.
                string executable = _executables.FirstOrDefault(File.Exists)
                    ?? throw new FileNotFoundException("A system installation of Dolphin is required to open a share.");
                using var process = _start(CreateStartInfo(executable)) ?? throw new InvalidOperationException("Dolphin could not start.");
                string name = ServicePrefix + process.Id.ToString(CultureInfo.InvariantCulture);
                while (service == null)
                {
                    if (process.HasExited) throw new InvalidOperationException("Dolphin exited before opening its window.");
                    service = (await GetWindowAsync(connection, name, token))?.Owner;
                    if (service == null) await Task.Delay(100, token);
                }
            }
            await SendOpenAsync(connection, service, url).WaitAsync(token);
            // A reply confirms delivery only. KIO performs SMB authentication
            // afterwards and displays any server/authentication error itself.
            try { await ActivateAsync(connection, service).WaitAsync(TimeSpan.FromSeconds(1), token); }
            catch (Exception) when (!cancellation.IsCancellationRequested) { /* Opening already succeeded. */ }
        }
        finally { _gate.Release(); }
    }

    internal static ProcessStartInfo CreateStartInfo(string executable)
    {
        var info = new ProcessStartInfo { FileName = executable, UseShellExecute = false };
        info.ArgumentList.Add("--new-window");
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        info.ArgumentList.Add(new Uri(string.IsNullOrEmpty(home) ? "/" : home + "/").AbsoluteUri);
        return info;
    }

    private async Task<string?> FindWindowAsync(Connection connection, CancellationToken token)
    {
        string[] names = await connection.CallMethodAsync(CreateBusMessage(connection, "ListNames"),
            (message, _) => message.GetBodyReader().ReadArrayOfString()).WaitAsync(token);
        string? first = null;
        foreach (string name in names.Where(name => name.StartsWith(ServicePrefix, StringComparison.Ordinal)))
        {
            var window = await GetWindowAsync(connection, name, token);
            if (window is not { } candidate) continue;
            if (candidate.Active) return candidate.Owner;
            first ??= candidate.Owner;
        }
        return first;
    }

    private async Task<(string Owner, bool Active)?> GetWindowAsync(Connection connection, string name, CancellationToken token)
    {
        if (!uint.TryParse(name.AsSpan(ServicePrefix.Length), NumberStyles.None, CultureInfo.InvariantCulture, out uint expectedPid))
            return null;
        try
        {
            string owner = await connection.CallMethodAsync(CreateBusMessage(connection, "GetNameOwner", name),
                (message, _) => message.GetBodyReader().ReadString()).WaitAsync(token);
            if (!owner.StartsWith(':')) return null;
            uint pid = await connection.CallMethodAsync(CreateBusMessage(connection, "GetConnectionUnixProcessID", owner),
                (message, _) => message.GetBodyReader().ReadUInt32()).WaitAsync(token);
            if (pid != expectedPid || !IsInstalledExecutable(pid)) return null;
            // The well-known name may move. All window calls use this unique connection.
            bool active = await connection.CallMethodAsync(CreateWindowMessage(connection, owner, "isActiveWindow"),
                (message, _) => message.GetBodyReader().ReadBool()).WaitAsync(TimeSpan.FromSeconds(1), token);
            return (owner, active);
        }
        catch (DBusException) { return null; } // The process or its window may be absent during startup or shutdown.
        catch (TimeoutException) { return null; }
    }

    private bool IsInstalledExecutable(uint pid)
    {
        if (!TryIdentifyFile($"/proc/{pid}/exe", out var peer)) return false;
        return _executables.Any(path => TryIdentifyFile(path, out var installed) &&
            peer.DeviceMajor == installed.DeviceMajor && peer.DeviceMinor == installed.DeviceMinor && peer.Inode == installed.Inode);
    }

    // Linux statx follows the kernel's /proc/PID/exe link. Device and inode
    // also distinguish identically named files in different mount namespaces.
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct FileIdentity
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(32)] public ulong Inode;
        [FieldOffset(136)] public uint DeviceMajor;
        [FieldOffset(140)] public uint DeviceMinor;
    }

    [DllImport("libc", EntryPoint = "statx")]
    private static extern int Statx(int dirFd, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, out FileIdentity identity);

    private static bool TryIdentifyFile(string path, out FileIdentity identity)
    {
        const uint inodeMask = 0x100; // STATX_INO from linux/stat.h
        return Statx(-100, path, 0, inodeMask, out identity) == 0 && (identity.Mask & inodeMask) != 0;
    }

    private static Task SendOpenAsync(Connection connection, string service, string url)
    {
        using var writer = connection.GetMessageWriter();
        writer.WriteMethodCallHeader(destination: service, path: WindowPath, @interface: WindowInterface, member: "openDirectories", signature: "asb");
        writer.WriteArray(new[] { url });
        writer.WriteBool(false);
        return connection.CallMethodAsync(writer.CreateMessage());
    }

    private static Task ActivateAsync(Connection connection, string service)
    {
        using var writer = connection.GetMessageWriter();
        writer.WriteMethodCallHeader(destination: service, path: WindowPath, @interface: WindowInterface, member: "activateWindow", signature: "s");
        writer.WriteString("");
        return connection.CallMethodAsync(writer.CreateMessage());
    }

    private static MessageBuffer CreateBusMessage(Connection connection, string member, string? argument = null)
    {
        using var writer = connection.GetMessageWriter();
        writer.WriteMethodCallHeader(destination: Bus, path: BusPath, @interface: Bus, member: member, signature: argument == null ? "" : "s");
        if (argument != null) writer.WriteString(argument);
        return writer.CreateMessage();
    }

    private static MessageBuffer CreateWindowMessage(Connection connection, string service, string member)
    {
        using var writer = connection.GetMessageWriter();
        writer.WriteMethodCallHeader(destination: service, path: WindowPath, @interface: WindowInterface, member: member);
        return writer.CreateMessage();
    }
}
