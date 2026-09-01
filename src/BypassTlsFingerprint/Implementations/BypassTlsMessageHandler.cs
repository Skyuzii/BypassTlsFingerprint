using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;

using BypassTlsFingerprint.Abstractions;

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
    private static readonly HashSet<string> ContentHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Allow", "Content-Disposition", "Content-Encoding", "Content-Language",
        "Content-Length", "Content-Location", "Content-MD5", "Content-Range",
        "Content-Type", "Expires", "Last-Modified",
    };

    private readonly BrowserTlsClient _tlsClient;
    private readonly HttpResponseParser _httpResponseParser = new HttpResponseParser();
    private readonly BypassConnectionPool _pool;

    public int Port { get; set; } = 443;

    public bool AllowAutoRedirect { get; set; } = true;

    public int MaxAutomaticRedirections { get; set; } = 50;

    public bool UseCookies { get; set; } = true;

    public bool UseProxy { get; set; } = true;

    public DecompressionMethods AutomaticDecompression { get; set; }

    public int MaxConnectionsPerServer { get; set; } = 50;

    public TimeSpan PooledConnectionIdleTimeout { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>Timeout applied to establishing a TCP connection. <see cref="TimeSpan.Zero"/> disables it.</summary>
    public TimeSpan ConnectTimeout { get; set; }

    /// <summary>Sends <c>Expect: 100-continue</c> before a request body.</summary>
    public bool ExpectContinue { get; set; }

    public string? ProxyHost { get; set; }

    public int? ProxyPort { get; set; }

    public ICredentials? ProxyCredentials { get; set; }

    public bool BypassProxyOnLocal { get; set; }

    public CookieContainer? CookieContainer { get; set; }

    public BypassTlsMessageHandler(BrowserTlsClient tlsClient)
    {
        _tlsClient = tlsClient;
        _pool = new BypassConnectionPool(PooledConnectionIdleTimeout, CreateConnectionAsync);
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri is not { } uri)
        {
            throw new ArgumentException("HttpRequestMessage.RequestUri cannot be null.");
        }

        if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new NotSupportedException($"Unsupported URI scheme '{uri.Scheme}'. Only http and https are supported.");
        }

        // Materialize the request body up-front (buffered) so it can be replayed across 307/308 redirects.
        byte[]? body = request.Content is null
            ? null
            : await request.Content.ReadAsByteArrayAsync(cancellationToken);

        return await SendWithRedirectsAsync(request, uri, body, redirectCount: 0, cancellationToken);
    }

    private async Task<HttpResponseMessage> SendWithRedirectsAsync(
        HttpRequestMessage request,
        Uri uri,
        byte[]? body,
        int redirectCount,
        CancellationToken ct)
    {
        HttpResponseMessage response = await SendSingleAsync(request, uri, body, ct);

        if (!AllowAutoRedirect
            || redirectCount >= MaxAutomaticRedirections
            || !TryGetRedirect(request, response, out HttpRequestMessage? nextRequest, out Uri? nextUri, ref body))
        {
            return response;
        }

        response.Dispose();
        return await SendWithRedirectsAsync(nextRequest!, nextUri!, body, redirectCount + 1, ct);
    }

    private async Task<HttpResponseMessage> SendSingleAsync(HttpRequestMessage request, Uri uri, byte[]? body, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var endpoint = new Endpoint(uri.Scheme, uri.Host, GetTargetPort(uri));
        BypassConnection connection = await _pool.RentAsync(endpoint, MaxConnectionsPerServer, ct);

        try
        {
            bool expectContinue = ExpectContinue && body is not null;
            byte[] payload = BuildRequestBody(request, uri, body, expectContinue);

            await connection.Stream.WriteAsync(payload, ct);

            Stream readStream = connection.Stream;
            if (expectContinue)
            {
                byte[] interim = await ReadResponseHeadBytesAsync(connection.Stream, ct);
                if (IsHttpStatus(interim, statusCode: 100))
                {
                    await connection.Stream.WriteAsync(body!, ct);
                }
                else
                {
                    // The server answered with a final status without waiting for the body: do not send it and
                    // re-parse from the already-read head.
                    readStream = new PrependStream(connection.Stream, interim);
                }
            }

            HttpResponse parsed = await _httpResponseParser.Parse(readStream, ct);

            // Return connection to the pool before cookie/decompression mapping; content is buffered anyway.
            connection.IsReusable = IsConnectionReusable(parsed);

            AddCookies(parsed, uri);

            if (AutomaticDecompression != DecompressionMethods.None)
            {
                parsed = DecompressResponse(parsed);
            }

            return BuildHttpResponseMessage(request, parsed);
        }
        catch
        {
            connection.IsReusable = false;
            throw;
        }
        finally
        {
            _pool.Return(connection, endpoint);
        }
    }

    private async Task<BypassConnection> CreateConnectionAsync(Endpoint endpoint, CancellationToken ct)
    {
        CancellationToken connectCt = WithConnectTimeout(ct);
        bool useProxy = IsProxyUsed(endpoint);
        TcpClient client;

        if (!useProxy)
        {
            client = new TcpClient();
            await client.ConnectAsync(endpoint.Host, endpoint.Port, connectCt);
        }
        else
        {
            client = await ConnectThroughProxyAsync(endpoint, connectCt);
        }

        Stream stream = client.GetStream();
        if (endpoint.Scheme == Uri.UriSchemeHttps)
        {
            _tlsClient.SetServerName(endpoint.Host);

            var protocol = new TlsClientProtocol(stream);
            protocol.Connect(_tlsClient);
            stream = protocol.Stream;
        }

        return new BypassConnection(client, stream, isTls: endpoint.Scheme == Uri.UriSchemeHttps, endpoint.Host);
    }

    private byte[] BuildRequestBody(HttpRequestMessage request, Uri uri, byte[]? body, bool expectContinue)
    {
        bool viaProxy = IsProxyUsed(new Endpoint(uri.Scheme, uri.Host, GetTargetPort(uri)));
        string target = BuildRequestTarget(request, uri, viaProxy && uri.Scheme == Uri.UriSchemeHttp);

        // HTTP/1.1 mandates CRLF line endings — never Environment.NewLine (which is "\\n" on Unix).
        var sb = new StringBuilder();
        sb.Append(request.Method).Append(' ').Append(target).Append(" HTTP/1.1\r\n");

        sb.Append("Host: ").Append(request.Headers.Host ?? uri.Host).Append("\r\n");

        if (AutomaticDecompression != DecompressionMethods.None)
        {
            sb.Append("Accept-Encoding: ").Append(BuildAcceptEncoding()).Append("\r\n");
        }

        foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers)
        {
            if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (string value in header.Value)
            {
                sb.Append(header.Key).Append(": ").Append(value).Append("\r\n");
            }
        }

        if (UseCookies && CookieContainer is not null)
        {
            string cookieHeader = CookieContainer.GetCookieHeader(uri);
            if (!string.IsNullOrEmpty(cookieHeader))
            {
                sb.Append("Cookie: ").Append(cookieHeader).Append("\r\n");
            }
        }

        if (body is not null)
        {
            sb.Append("Content-Length: ").Append(body.Length).Append("\r\n");

            foreach (KeyValuePair<string, IEnumerable<string>> header in request.Content!.Headers)
            {
                if (header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (string value in header.Value)
                {
                    sb.Append(header.Key).Append(": ").Append(value).Append("\r\n");
                }
            }

            if (expectContinue)
            {
                sb.Append("Expect: 100-continue\r\n");
            }
        }

        sb.Append("\r\n");

        byte[] head = Encoding.UTF8.GetBytes(sb.ToString());
        if (body is null || expectContinue)
        {
            // ExpectContinue sends the body separately only after the server's "100 Continue".
            return head;
        }

        var result = new byte[head.Length + body.Length];
        Buffer.BlockCopy(head, srcOffset: 0, result, dstOffset: 0, head.Length);
        Buffer.BlockCopy(body, srcOffset: 0, result, head.Length, body.Length);
        return result;
    }

    private string BuildRequestTarget(HttpRequestMessage request, Uri uri, bool absoluteForm)
    {
        if (absoluteForm)
        {
            // Plaintext HTTP through a proxy uses absolute-form (no CONNECT).
            return uri.AbsoluteUri;
        }

        return uri.PathAndQuery;
    }

    private string BuildAcceptEncoding()
    {
        var encodings = new List<string>();
        if (AutomaticDecompression.HasFlag(DecompressionMethods.GZip))
        {
            encodings.Add("gzip");
        }

        if (AutomaticDecompression.HasFlag(DecompressionMethods.Deflate))
        {
            encodings.Add("deflate");
        }

        if (AutomaticDecompression.HasFlag(DecompressionMethods.Brotli))
        {
            encodings.Add("br");
        }

        return encodings.Count == 0 ? "identity" : string.Join(", ", encodings);
    }

    private HttpResponse DecompressResponse(HttpResponse parsed)
    {
        string? contentEncoding = GetHeader(parsed.Headers, "Content-Encoding");
        if (string.IsNullOrEmpty(contentEncoding) || parsed.Content.Length == 0)
        {
            return parsed;
        }

        Stream? decompressor = null;
        string token = contentEncoding.Split(',')[0].Trim();

        if ((AutomaticDecompression & DecompressionMethods.GZip) != 0 && token.Equals("gzip", StringComparison.OrdinalIgnoreCase))
        {
            decompressor = new GZipStream(new MemoryStream(parsed.Content), CompressionMode.Decompress);
        }
        else if ((AutomaticDecompression & DecompressionMethods.Deflate) != 0 && token.Equals("deflate", StringComparison.OrdinalIgnoreCase))
        {
            decompressor = new DeflateStream(new MemoryStream(parsed.Content), CompressionMode.Decompress);
        }
        else if ((AutomaticDecompression & DecompressionMethods.Brotli) != 0 && token.Equals("br", StringComparison.OrdinalIgnoreCase))
        {
            decompressor = new BrotliStream(new MemoryStream(parsed.Content), CompressionMode.Decompress);
        }

        if (decompressor is null)
        {
            return parsed;
        }

        using (decompressor)
        {
            using var output = new MemoryStream();
            decompressor.CopyTo(output);
            parsed.Content = output.ToArray();
        }

        // The body is now decoded: drop the headers that described the on-the-wire bytes.
        parsed.Headers.RemoveAll(h =>
            h.Key.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase) ||
            h.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
            h.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase));

        return parsed;
    }

    private HttpResponseMessage BuildHttpResponseMessage(HttpRequestMessage request, HttpResponse parsed)
    {
        var response = new HttpResponseMessage
        {
            StatusCode = (HttpStatusCode)parsed.StatusCode,
            Version = ParseVersion(parsed.HttpVersion),
            RequestMessage = request,
        };

        var content = new ByteArrayContent(parsed.Content);
        response.Content = content;

        foreach (KeyValuePair<string, string> header in parsed.Headers)
        {
            if (header.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
            {
                // We always deliver a fully buffered body with a Content-Length; drop framing meta.
                continue;
            }

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

    private void AddCookies(HttpResponse parsed, Uri uri)
    {
        if (!UseCookies || CookieContainer is null)
        {
            return;
        }

        string[] setCookies = parsed.Headers
            .Where(h => h.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            .Select(h => h.Value)
            .ToArray();

        if (setCookies.Length == 0)
        {
            return;
        }

        CookieContainer.SetCookies(uri, string.Join(", ", setCookies));
    }

    private bool TryGetRedirect(
        HttpRequestMessage request,
        HttpResponseMessage response,
        out HttpRequestMessage? nextRequest,
        out Uri? nextUri,
        ref byte[]? body)
    {
        nextRequest = null;
        nextUri = null;

        var status = (int)response.StatusCode;
        if (status < 300 || status >= 400 ||
            status is 304 or 305 or 306 ||
            response.Headers.Location is not { } location ||
            response.RequestMessage?.RequestUri is not { } baseUri)
        {
            return false;
        }

        nextUri = location.IsAbsoluteUri ? location : new Uri(baseUri, location.ToString());

        bool switchToGet = status is 301 or 302 or 303 &&
                           request.Method != HttpMethod.Get && request.Method != HttpMethod.Head;

        var next = new HttpRequestMessage(switchToGet ? HttpMethod.Get : request.Method, nextUri);

        foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers)
        {
            if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
                header.Key.Equals("Cookie", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            next.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        if (!switchToGet && body is not null && request.Content is not null)
        {
            // Preserve body + content headers for 307/308-style redirects.
            next.Content = new ByteArrayContent(body);
            foreach (KeyValuePair<string, IEnumerable<string>> header in request.Content.Headers)
            {
                if (header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                next.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }
        else
        {
            body = null;
        }

        nextRequest = next;
        return true;
    }

    private async Task<TcpClient> ConnectThroughProxyAsync(Endpoint endpoint, CancellationToken ct)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(ProxyHost!, ProxyPort!.Value, ct);

        string? authorizationHeader = BuildProxyAuthorizationHeader();
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
                $"Failed to connect to the proxy server {ProxyHost}:{ProxyPort}. Response: {proxyResponse}");
        }

        return new TcpClient
        {
            Client = socket
        };
    }

    private string? BuildProxyAuthorizationHeader()
    {
        if (ProxyCredentials is null)
        {
            return null;
        }

        NetworkCredential credentials = ProxyCredentials.GetCredential(
            new Uri($"http://{ProxyHost}:{ProxyPort}/"), "Basic") ?? new NetworkCredential();

        var userPass = $"{credentials.UserName}:{credentials.Password}";
        return $"Proxy-Authorization: Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes(userPass))}";
    }

    private bool IsProxyUsed(Endpoint endpoint)
    {
        if (!UseProxy || string.IsNullOrEmpty(ProxyHost) || ProxyPort is null)
        {
            return false;
        }

        if (BypassProxyOnLocal &&
            (endpoint.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
             Uri.TryCreate($"http://{endpoint.Host}", UriKind.Absolute, out Uri? u) && u.IsLoopback))
        {
            return false;
        }

        return true;
    }

    /// <summary>Resolves the connect port, honouring an explicit URI port, the <see cref="Port"/> override
    /// for HTTPS, and the default 80 for plaintext HTTP.</summary>
    private int GetTargetPort(Uri uri)
    {
        if (!uri.IsDefaultPort)
        {
            return uri.Port;
        }

        return uri.Scheme == Uri.UriSchemeHttps ? Port : 80;
    }

    private CancellationToken WithConnectTimeout(CancellationToken ct)
    {
        if (ConnectTimeout <= TimeSpan.Zero)
        {
            return ct;
        }

        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(ConnectTimeout);
        return cts.Token;
    }

    private static bool IsConnectionReusable(HttpResponse parsed)
    {
        bool knownFraming =
            GetHeader(parsed.Headers, "Content-Length") is not null ||
            GetHeader(parsed.Headers, "Transfer-Encoding") is not null;

        if (!knownFraming)
        {
            return false;
        }

        string? connection = GetHeader(parsed.Headers, "Connection");
        if (connection?.Contains("close", StringComparison.OrdinalIgnoreCase) == true)
        {
            return false;
        }

        return true;
    }

    private static async Task<byte[]> ReadResponseHeadBytesAsync(Stream stream, CancellationToken ct)
    {
        var head = new List<byte>(512);
        var one = new byte[1];

        while (true)
        {
            int n = await stream.ReadAsync(one, ct);
            if (n == 0)
            {
                break;
            }

            head.Add(one[0]);
            if (head.Count >= 4 &&
                head[^4] == (byte)'\r' && head[^3] == (byte)'\n' &&
                head[^2] == (byte)'\r' && head[^1] == (byte)'\n')
            {
                break;
            }
        }

        return head.ToArray();
    }

    private static bool IsHttpStatus(byte[] head, int statusCode)
    {
        string headText = Encoding.ASCII.GetString(head);
        string firstLine = headText.Contains('\n') ? headText[..headText.IndexOf('\n')] : headText;
        string[] parts = firstLine.Trim().Split(' ');
        return parts.Length >= 2 && parts[1] == statusCode.ToString();
    }

    private static bool IsContentHeader(string name)
    {
        return ContentHeaders.Contains(name);
    }

    private static string? GetHeader(List<KeyValuePair<string, string>> headers, string name)
    {
        foreach (KeyValuePair<string, string> header in headers)
        {
            if (string.Equals(header.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return header.Value;
            }
        }

        return null;
    }

    private static Version ParseVersion(string httpVersion)
    {
        return httpVersion switch
        {
            "HTTP/1.0" => HttpVersion.Version10,
            "HTTP/1.1" => HttpVersion.Version11,
            _ => HttpVersion.Version11
        };
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _pool.Dispose();
        }

        base.Dispose(disposing);
    }
}
