using System.Net;
using System.Net.Sockets;

namespace TKNetUI;

internal static class ResultSort
{
    public static uint IPv4Key(string ip)
    {
        if (!IPAddress.TryParse(ip, out var address) || address.AddressFamily != AddressFamily.InterNetwork)
            return 0;
        byte[] bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }
}
