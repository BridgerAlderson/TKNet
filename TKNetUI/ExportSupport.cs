using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace TKNetUI;

// File-provider streams may open an existing file without truncating it.
public static class ExportSupport
{
    public const int MaxScopeCharacters = 1024 * 1024;

    public static string Csv(params string?[] fields) => string.Join(",", fields.Select(CsvCell));

    private static string CsvCell(string? value)
    {
        value ??= "";
        string significant = value.TrimStart();
        // CSV quoting alone does not prevent spreadsheet formula evaluation.
        if ((significant.Length > 0 && "=+-@".Contains(significant[0])) ||
            (value.Length > 0 && (value[0] == '\t' || value[0] == '\r' || value[0] == '\n')))
            value = "'" + value;
        return value.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0
            ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }

    public static string[] ConfirmedIPs(IEnumerable<AliveResult> results)
    {
        var addresses = new HashSet<string>(StringComparer.Ordinal);
        foreach (var result in results.Where(result => result.IsAlive))
        {
            if (!IPAddress.TryParse(result.IP, out var address) ||
                address.AddressFamily != AddressFamily.InterNetwork || address.ToString() != result.IP)
                throw new InvalidDataException("A confirmed result contains an invalid IPv4 address.");
            addresses.Add(result.IP);
        }
        return addresses.OrderBy(ResultSort.IPv4Key).ToArray();
    }

    public static async Task WriteTextAsync(Stream stream, string text, bool includeBom = true)
    {
        if (stream.CanSeek) { stream.Position = 0; stream.SetLength(0); }
        await using var writer = new StreamWriter(stream, new UTF8Encoding(includeBom), 4096, leaveOpen: true);
        await writer.WriteAsync(text);
    }

    public static async Task<string> ReadScopeAsync(Stream stream)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8, true, 4096, leaveOpen: true);
        var text = new StringBuilder();
        char[] buffer = new char[4096];
        int read;
        while ((read = await reader.ReadAsync(buffer, 0, buffer.Length)) > 0)
        {
            if (text.Length + read > MaxScopeCharacters)
                throw new InvalidDataException("Scope file exceeds the 1 MiB character limit.");
            text.Append(buffer, 0, read);
        }
        return text.ToString();
    }
}
