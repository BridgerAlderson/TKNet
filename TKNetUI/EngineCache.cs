using System;
using System.IO;
using System.Security.Cryptography;

namespace TKNetUI;

public static class EngineCache
{
    // Validate cached bytes, not just the directory name, before execution.
    public static string Publish(Stream resource, string cacheRoot, string name)
    {
        string hash = Convert.ToHexString(SHA256.HashData(resource));
        resource.Position = 0;
        string directory = Path.Combine(cacheRoot, hash);
        Directory.CreateDirectory(directory);
        string destination = Path.Combine(directory, name);
        if (!Matches(destination, hash))
        {
            string temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write)) resource.CopyTo(file);
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
                // Another process may have finished while we copied. Only replace a damaged entry.
                var existing = new FileInfo(destination);
                bool repair = existing.Exists || existing.LinkTarget != null;
                if (!repair || !Matches(destination, hash))
                {
                    try { File.Move(temporary, destination, overwrite: repair); }
                    catch (Exception error) when ((error is IOException or UnauthorizedAccessException) && Matches(destination, hash))
                    {
                        // The winner installed the expected bytes before our move completed.
                    }
                }
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(destination, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return destination;
    }

    private static bool Matches(string path, string hash)
    {
        var entry = new FileInfo(path);
        if (!entry.Exists || entry.Attributes.HasFlag(FileAttributes.ReparsePoint)) return false;
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(file)) == hash;
    }
}
