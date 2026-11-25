using System;
using System.Collections.Generic;
using System.Globalization;

namespace TKNetUI
{
    // Same IPv4 syntax, usable-host rules and interval deduplication as ParseTargets.
    public static class ScopeParser
    {
        public readonly struct Summary
        {
            public long Hosts { get; init; }
            public int ValidEntries { get; init; }
            public int InvalidLines { get; init; }
            public string? FirstError { get; init; }
        }

        public static Summary Analyze(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return new Summary();
            var intervals = new List<(uint Start, uint End)>();
            int valid = 0, invalid = 0;
            string? firstError = null;
            foreach (string raw in input.Replace(",", "\n").Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                string? error = ParseInterval(line, out uint start, out uint end);
                if (error != null) { invalid++; firstError ??= $"{line} — {error}"; }
                else { valid++; intervals.Add((start, end)); }
            }
            intervals.Sort((a, b) => a.Start.CompareTo(b.Start));
            ulong hosts = 0, rangeStart = 0, rangeEnd = 0;
            bool hasRange = false;
            foreach (var interval in intervals)
            {
                if (!hasRange) { rangeStart = interval.Start; rangeEnd = interval.End; hasRange = true; }
                else if ((ulong)interval.Start <= rangeEnd + 1) rangeEnd = Math.Max(rangeEnd, interval.End);
                else { hosts += rangeEnd - rangeStart + 1; rangeStart = interval.Start; rangeEnd = interval.End; }
            }
            if (hasRange) hosts += rangeEnd - rangeStart + 1;
            return new Summary { Hosts = (long)hosts, ValidEntries = valid, InvalidLines = invalid, FirstError = firstError };
        }

        private static string? ParseInterval(string line, out uint start, out uint end)
        {
            start = end = 0;
            if (line.Contains('/'))
            {
                string[] parts = line.Split('/');
                if (parts.Length != 2 || !TryParseV4(parts[0], out uint ip) ||
                    !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int prefix) || prefix > 32)
                    return "invalid IPv4 CIDR";
                uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
                start = ip & mask;
                end = start | ~mask;
                if (prefix < 31) { start++; end--; }
            }
            else if (line.Contains('-'))
            {
                string[] parts = line.Split('-');
                if (parts.Length != 2 || !TryParseV4(parts[0].Trim(), out start)) return "invalid start IP";
                string last = parts[1].Trim();
                // A short decimal is a last octet, never .NET's abbreviated IPv4 syntax.
                if (!TryParseV4(last, out end))
                {
                    if (!int.TryParse(last, NumberStyles.Integer, CultureInfo.InvariantCulture, out int octet) || octet < 0 || octet > 255)
                        return "invalid end IP";
                    end = (start & 0xffffff00u) | (uint)octet;
                }
                if (end < start) return "start IP greater than end IP";
            }
            else
            {
                if (!TryParseV4(line, out start)) return "invalid IPv4 address";
                end = start;
            }
            return null;
        }

        private static bool TryParseV4(string text, out uint value)
        {
            value = 0;
            var parts = text.Split('.');
            if (parts.Length != 4) return false;
            foreach (string part in parts)
            {
                if (part.Length == 0 || (part.Length > 1 && part[0] == '0') ||
                    !byte.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out byte octet)) return false;
                value = (value << 8) | octet;
            }
            return true;
        }
    }
}
