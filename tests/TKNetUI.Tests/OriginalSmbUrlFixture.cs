using System.Text;

// Frozen from the initial MainWindow.BuildSmbUrl implementation, before the
// quality audit. Used for differential compatibility checks, not production.
internal static class OriginalSmbUrlFixture
{
    public static string Build(string ip, string? share, string user, string pass, string domain, bool useHash)
    {
        var sb = new StringBuilder("smb://");
        if (!string.IsNullOrWhiteSpace(user))
        {
            if (!string.IsNullOrWhiteSpace(domain)) sb.Append(Uri.EscapeDataString(domain)).Append(';');
            sb.Append(Uri.EscapeDataString(user));
            if (!useHash && !string.IsNullOrEmpty(pass)) sb.Append(':').Append(Uri.EscapeDataString(pass));
            sb.Append('@');
        }
        sb.Append(ip).Append('/');
        if (!string.IsNullOrWhiteSpace(share)) sb.Append(Uri.EscapeDataString(share));
        return sb.ToString();
    }
}
