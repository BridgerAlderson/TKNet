using Avalonia;
using System;
using System.IO;

namespace TKNetUI;

class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        try
        {
            AppDomain.CurrentDomain.UnhandledException += (_, e) => RecordCrash(e.ExceptionObject.ToString() ?? "Unknown error");
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            RecordCrash(ex.ToString());
            Environment.ExitCode = 1;
        }
    }

    private static void RecordCrash(string message)
    {
        // Diagnostic I/O must never throw while already handling an exception.
        try
        {
            string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TKNet", "Logs");
            Directory.CreateDirectory(directory);
            string path = Path.Combine(directory, "crash.log");
            if (File.Exists(path) && new FileInfo(path).Length > 1024 * 1024)
                File.Move(path, path + ".previous", overwrite: true);
            File.AppendAllText(path, $"[{DateTimeOffset.UtcNow:O}] {message}\n\n");
        }
        catch { /* No usable log location; preserve the original failure. */ }
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
#if DEBUG
            .WithDeveloperTools()
#endif
            .WithInterFont()
            .LogToTrace();
}
