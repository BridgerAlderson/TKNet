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
                try { File.Move(temporary, destination, overwrite: true); }
                catch (IOException) when (Matches(destination, hash)) { /* Another instance published identical bytes. */ }
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(destination, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return destination;
    }

    private static bool Matches(string path, string hash)
    {
        if (!File.Exists(path) || new FileInfo(path).LinkTarget != null) return false;
        using var file = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(file)) == hash;
    }
}
