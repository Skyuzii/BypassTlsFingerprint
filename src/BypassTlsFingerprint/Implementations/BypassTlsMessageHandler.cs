using System.Net;
using System.Net.Sockets;
using System.Text;

using BypassTlsFingerprint.Abstractions;
using BypassTlsFingerprint.Implementations.Models;
using BypassTlsFingerprint.Implementations.Parsers;

using Org.BouncyCastle.Tls;

namespace BypassTlsFingerprint.Implementations;

/// <summary>
/// A transport <see cref="HttpMessageHandler"/> that performs HTTP/1.1 requests over a TLS connection
/// based on <see cref="BrowserTlsClient"/> (a spoofed browser JA3 fingerprint) instead of the standard
/// <see cref="SocketsHttpHandler"/>. It is plugged into an <see cref="HttpClient"/> via
/// <c>new HttpClient(handler)</c>.
/// </summary>
public sealed class BypassTlsMessageHandler : HttpMessageHandler
{
    private const int MaxRedirects = 10;

    private static readonly HashSet<string> ContentHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Allow", "Content-Disposition", "Content-Encoding", "Content-Language",
        "Content-Length", "Content-Location", "Content-MD5", "Content-Range",
        "Content-Type", "Expires", "Last-Modified",
    };

    private readonly BrowserTlsClient _tlsClient;
    private readonly HttpParser _httpParser = new HttpParser();

    public int Port { get; set; } = 443;

    public bool AllowAutoRedirect { get; set; } = true;

    public string? ProxyHost { get; set; }

    public int? ProxyPort { get; set; }

    public CookieContainer? CookieContainer { get; set; }

    public BypassTlsMessageHandler(BrowserTlsClient tlsClient)
    {
        _tlsClient = tlsClient;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri is not { } uri)
        {
            throw new ArgumentException("HttpRequestMessage.RequestUri cannot be null.");
        }

        return await SendCoreAsync(request, uri, allowRedirect: AllowAutoRedirect, maxRedirects: MaxRedirects, cancellationToken);
    }

    private async Task<HttpResponseMessage> SendCoreAsync(
        HttpRequestMessage request,
        Uri uri,
        bool allowRedirect,
        int maxRedirects,
        CancellationToken ct)
    {
        _tlsClient.SetServerName(uri.Host);

        TlsClientProtocol? protocol = null;

        try
        {
            using TcpClient client = await CreateTcpClientAsync(uri.Host, Port, ct);
            ct.ThrowIfCancellationRequested();

            protocol = new TlsClientProtocol(client.GetStream());
            protocol.Connect(_tlsClient);

            byte[] payload = await BuildRequestBodyAsync(request, uri, ct);
            await protocol.Stream.WriteAsync(payload, ct);

            string rawResponse = await ReadResponseAsync(protocol.Stream, ct);
            HttpResponse parsed = await _httpParser.ParseHttpResponse(rawResponse);

            AddCookies(parsed, uri);
            HttpResponseMessage response = ToHttpResponseMessage(request, parsed);

            if (allowRedirect
                && maxRedirects > 0
                && parsed.Headers.TryGetValue("Location", out string? location)
                && !string.IsNullOrWhiteSpace(location))
            {
                var nextUri = new Uri(uri, location);
                return await SendCoreAsync(
                    BuildRedirectRequest(request, nextUri),
                    nextUri,
                    allowRedirect: true,
                    maxRedirects - 1,
                    ct);
            }

            return response;
        }
        finally
        {
            if (protocol != null)
            {
                protocol.Close();

                if (protocol.Stream != null)
                {
                    await protocol.Stream.DisposeAsync();
                }
            }
        }
    }

    private async Task<byte[]> BuildRequestBodyAsync(HttpRequestMessage request, Uri uri, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{request.Method} {uri.PathAndQuery} HTTP/1.1");

        string host = request.Headers.Host ?? uri.Host;
        sb.AppendLine($"Host: {host}");
        sb.AppendLine("Connection: close");

        foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers)
        {
            if (string.Equals(header.Key, "Host", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (string value in header.Value)
            {
                sb.AppendLine($"{header.Key}: {value}");
            }
        }

        HttpContent? content = request.Content;
        byte[]? body = content == null ? null : await content.ReadAsByteArrayAsync(ct);

        if (CookieContainer != null)
        {
            string cookieHeader = CookieContainer.GetCookieHeader(uri);
            if (!string.IsNullOrEmpty(cookieHeader))
            {
                sb.AppendLine($"Cookie: {cookieHeader}");
            }
        }

        if (body != null)
        {
            sb.AppendLine($"Content-Length: {body.Length}");

            foreach (KeyValuePair<string, IEnumerable<string>> header in content!.Headers)
            {
                if (string.Equals(header.Key, "Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (string value in header.Value)
                {
                    sb.AppendLine($"{header.Key}: {value}");
                }
            }
        }

        sb.AppendLine();

        byte[] head = Encoding.UTF8.GetBytes(sb.ToString());
        if (body is null || body.Length == 0)
        {
            return head;
        }

        var result = new byte[head.Length + body.Length];
        Buffer.BlockCopy(head, srcOffset: 0, result, dstOffset: 0, head.Length);
        Buffer.BlockCopy(body, srcOffset: 0, result, head.Length, body.Length);
        return result;
    }

    private static async Task<string> ReadResponseAsync(Stream stream, CancellationToken ct)
    {
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync(ct);
    }

    private void AddCookies(HttpResponse parsed, Uri uri)
    {
        if (CookieContainer == null)
        {
            return;
        }

        CookieContainer.Add(uri, parsed.Cookies);
    }

    private HttpResponseMessage ToHttpResponseMessage(HttpRequestMessage request, HttpResponse parsed)
    {
        var response = new HttpResponseMessage
        {
            StatusCode = (HttpStatusCode)parsed.StatusCode,
            Version = ParseVersion(parsed.HttpVersion),
            RequestMessage = request,
        };

        var content = new ByteArrayContent(
            parsed.Content is null ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(parsed.Content));
        response.Content = content;

        foreach (KeyValuePair<string, string> header in parsed.Headers)
        {
            if (IsContentHeader(header.Key))
            {
                content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            else
            {
                response.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        return response;
    }

    private static HttpRequestMessage BuildRedirectRequest(HttpRequestMessage source, Uri nextUri)
    {
        var next = new HttpRequestMessage(source.Method, nextUri);

        foreach (KeyValuePair<string, IEnumerable<string>> header in source.Headers)
        {
            if (string.Equals(header.Key, "Host", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            next.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        return next;
    }

    private async Task<TcpClient> CreateTcpClientAsync(string host, int port, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(ProxyHost) || ProxyPort == null)
        {
            var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(host, port, ct);
            return tcpClient;
        }

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(ProxyHost, ProxyPort.Value, ct);

        byte[] connectMessage = Encoding.UTF8.GetBytes($"CONNECT {host}:{port} HTTP/1.1{Environment.NewLine}{Environment.NewLine}");
        await socket.SendAsync(connectMessage, SocketFlags.None, ct);

        var receiveBuffer = new byte[1024];
        int received = await socket.ReceiveAsync(receiveBuffer, SocketFlags.None, ct);

        string response = Encoding.UTF8.GetString(receiveBuffer, index: 0, received);
        if (!response.Contains("200"))
        {
            throw new Exception($"Failed to connect to the proxy server {ProxyHost}:{ProxyPort}. Response: {response}");
        }

        return new TcpClient
        {
            Client = socket
        };
    }

    private static bool IsContentHeader(string name)
    {
        return ContentHeaders.Contains(name);
    }

    private static Version ParseVersion(string httpVersion)
    {
        return httpVersion switch
        {
            "HTTP/1.0" => HttpVersion.Version10,
            "HTTP/1.1" => HttpVersion.Version11,
            "HTTP/2" => HttpVersion.Version20,
            _ => HttpVersion.Version11
        };
    }
}
