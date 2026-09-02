using System.Buffers;
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

        // Read the CONNECT response head fully: a single ReceiveAsync may return only a partial status
        // line, and for a 200 with no body the head *is* the whole response. We read until \r\n\r\n.
        string proxyResponse = await ReadConnectResponseAsync(socket, ct);

        // A 2xx status (most commonly 200) means the tunnel is established. Anything else is a failure.
        if (!IsSuccessStatus(proxyResponse))
        {
            socket.Dispose();
            throw new HttpRequestException(
                $"Failed to connect to the proxy server {proxyAddress}. Response: {proxyResponse}");
        }

        return new TcpClient
        {
            Client = socket,
        };
    }

    /// <summary>
    /// Resolves whether <paramref name="destination"/> should be proxied and, if so, the proxy address.
    /// Loopback and hosts the proxy reports as bypassed are contacted directly.
    /// </summary>
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

    /// <summary>
    /// Reads the CONNECT response head (status line + headers up to the blank line) from the socket,
    /// handling partial reads and framing correctly — unlike a single ReceiveAsync which may return
    /// fewer bytes than the head, or more (the start of the tunnelled TLS handshake).
    /// </summary>
    private static async Task<string> ReadConnectResponseAsync(Socket socket, CancellationToken ct)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(1024);
        var length = 0;

        try
        {
            while (true)
            {
                if (length == buffer.Length)
                {
                    // Headers on a CONNECT response are tiny; a 1KB cap is generous. Refuse to grow
                    // unbounded on a misbehaving proxy.
                    throw new HttpRequestException("Proxy CONNECT response head exceeded 1024 bytes.");
                }

                int read = await socket.ReceiveAsync(buffer.AsMemory(length), SocketFlags.None, ct);
                if (read == 0)
                {
                    throw new EndOfStreamException("Connection closed before the proxy CONNECT response completed.");
                }

                length += read;

                int headerEnd = IndexOfCrlfCrlf(buffer, length);
                if (headerEnd >= 0)
                {
                    return Encoding.ASCII.GetString(buffer, index: 0, headerEnd + 4);
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static bool IsSuccessStatus(string response)
    {
        // Status line: "HTTP/1.1 200 Connection established". A 2xx code means the tunnel is up.
        ReadOnlySpan<char> head = response.AsSpan();
        int firstSpace = head.IndexOf(' ');
        if (firstSpace < 0)
        {
            return false;
        }

        int codeStart = firstSpace + 1;
        int secondSpace = head.Slice(codeStart).IndexOf(' ');
        ReadOnlySpan<char> code = secondSpace < 0 ? head.Slice(codeStart) : head.Slice(codeStart, secondSpace);

        return code.Length == 3 && code[0] == '2';
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

    private static int IndexOfCrlfCrlf(byte[] buffer, int length)
    {
        int limit = length - 4;
        for (var i = 0; i <= limit; i++)
        {
            if (buffer[i] == (byte)'\r' && buffer[i + 1] == (byte)'\n' &&
                buffer[i + 2] == (byte)'\r' && buffer[i + 3] == (byte)'\n')
            {
                return i;
            }
        }

        return -1;
    }
}
