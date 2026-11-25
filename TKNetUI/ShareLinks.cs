using System;
using System.Net;
using System.Net.Sockets;

namespace TKNetUI;

// Public/copyable links never contain credentials. Authenticated links are only
// for the private, in-memory handoff to Dolphin, never logs or process arguments.
public static class ShareLinks
{
    private static void Validate(string ip, string? share)
    {
        if (!IPAddress.TryParse(ip, out var address) || address.AddressFamily != AddressFamily.InterNetwork || address.ToString() != ip)
            throw new ArgumentException("A canonical IPv4 host address is required.");
        if (share != null && (share is "." or ".." || share.IndexOfAny(new[] { '/', '\\', '\0', '\r', '\n' }) >= 0))
            throw new ArgumentException("Invalid share name.");
    }

    public static string Url(string ip, string? share)
    {
        Validate(ip, share);
        return "smb://" + ip + "/" + (string.IsNullOrEmpty(share) ? "" : Uri.EscapeDataString(share));
    }

    public static string Unc(string ip, string? share)
    {
        Validate(ip, share);
        return @"\\" + ip + (string.IsNullOrEmpty(share) ? "" : @"\" + share);
    }

    internal static string DolphinUrl(string ip, string? share, string? user, string? password, string? domain, bool useHash)
    {
        string location = Url(ip, share);
        if (string.IsNullOrWhiteSpace(user)) return location;
        string identity = string.IsNullOrWhiteSpace(domain) ? "" : Uri.EscapeDataString(domain) + ";";
        identity += Uri.EscapeDataString(user);
        // KIO accepts passwords, not NTLM hashes. Preserve the original prompt
        // behavior in hash mode without ever passing the hash as a password.
        if (!useHash && !string.IsNullOrEmpty(password)) identity += ":" + Uri.EscapeDataString(password);
        return "smb://" + identity + "@" + location[6..];
    }
}
