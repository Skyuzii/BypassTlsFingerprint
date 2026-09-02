using System.Net;
using System.Net.Sockets;
using System.Text;

namespace BypassTlsFingerprint;

/// <summary>Establishes outbound TCP connections through an HTTP CONNECT proxy.</summary>
internal static class ProxyConnection
{
    public static async Task<TcpClient> ConnectThroughProxyAsync(
        Endpoint endpoint,
        Uri proxyAddress,
        ICredentials? credentials,
        CancellationToken ct)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxyAddress.Host, GetProxyPort(proxyAddress), ct);

        string? authorizationHeader = BuildProxyAuthorizationHeader(proxyAddress, credentials);
        byte[] connectMessage = Encoding.UTF8.GetBytes(
            $"CONNECT {endpoint.Host}:{endpoint.Port} HTTP/1.1\r\n" +
            $"Host: {endpoint.Host}:{endpoint.Port}\r\n" +
            (authorizationHeader is null ? "" : $"{authorizationHeader}\r\n") +
            "\r\n");
        await socket.SendAsync(connectMessage, SocketFlags.None, ct);

        var receiveBuffer = new byte[1024];
        int received = await socket.ReceiveAsync(receiveBuffer, SocketFlags.None, ct);
        string proxyResponse = Encoding.UTF8.GetString(receiveBuffer, index: 0, received);

        if (!proxyResponse.Contains(" 200 "))
        {
            throw new HttpRequestException(
                $"Failed to connect to the proxy server {proxyAddress}. Response: {proxyResponse}");
        }

        return new TcpClient
        {
            Client = socket
        };
    }

    public static bool TryResolveProxy(Uri destination, bool useProxy, IWebProxy? proxy, out Uri? proxyAddress)
    {
        proxyAddress = null;
        if (!useProxy || proxy is null)
        {
            return false;
        }

        // Loopback is never proxied — parity with HttpClient, and unlike WebProxy.BypassProxyOnLocal this
        // also covers IP literals (127.0.0.1 / ::1), which that flag does not treat as "local".
        if (IsLoopbackHost(destination.Host))
        {
            return false;
        }

        if (proxy.IsBypassed(destination))
        {
            return false;
        }

        proxyAddress = proxy.GetProxy(destination);
        return proxyAddress is not null;
    }

    public static bool IsLoopbackHost(string host)
    {
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IPAddress.TryParse(host, out IPAddress? address) && IPAddress.IsLoopback(address);
    }

    private static int GetProxyPort(Uri proxyAddress)
    {
        if (!proxyAddress.IsDefaultPort)
        {
            return proxyAddress.Port;
        }

        return proxyAddress.Scheme == Uri.UriSchemeHttps ? 443 : 80;
    }

    private static string? BuildProxyAuthorizationHeader(Uri proxyAddress, ICredentials? credentials)
    {
        if (credentials is null)
        {
            return null;
        }

        NetworkCredential credential = credentials.GetCredential(proxyAddress, "Basic") ?? new NetworkCredential();

        var userPass = $"{credential.UserName}:{credential.Password}";
        return $"Proxy-Authorization: Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes(userPass))}";
    }
}
