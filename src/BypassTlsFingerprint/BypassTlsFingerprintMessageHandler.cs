using System.Net;
using System.Net.Sockets;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace BypassTlsFingerprint;

public sealed class BypassTlsFingerprintMessageHandler : HttpMessageHandler
{
    private readonly TlsFingerprintClient _tlsClient;
    private readonly HttpResponseParser _httpResponseParser = new HttpResponseParser();
    private readonly HttpConnectionPool _pool;

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

    /// <summary>
    /// The proxy used when <see cref="UseProxy"/> is true, mirroring <see cref="HttpClientHandler.Proxy"/>.
    /// Defaults to <see cref="HttpClient.DefaultProxy"/> so environment variables (HTTP_PROXY/HTTPS_PROXY/NO_PROXY)
    /// are honoured just like with a standard <see cref="HttpClient"/>. Hosts the proxy reports as bypassed
    /// (e.g. loopback via <see cref="WebProxy.BypassProxyOnLocal"/>) are contacted directly. Set to null to
    /// disable proxying.
    /// </summary>
    public IWebProxy? Proxy { get; set; } = HttpClient.DefaultProxy;

    /// <summary>Fallback credentials used for proxy authentication when <see cref="Proxy"/> carries none.</summary>
    public ICredentials? DefaultProxyCredentials { get; set; }

    public CookieContainer? CookieContainer { get; set; }

    /// <summary>
    /// Creates a handler that impersonates the given browser fingerprint. The TLS client itself
    /// (<see cref="TlsFingerprintClient"/>) is constructed internally — consumers only describe the
    /// impersonation with a <see cref="TlsFingerprint"/>.
    /// </summary>
    public BypassTlsFingerprintMessageHandler(TlsFingerprint fingerprint)
    {
        _tlsClient = new TlsFingerprintClient(new BcTlsCrypto(new SecureRandom()), fingerprint);
        _pool = new HttpConnectionPool(PooledConnectionIdleTimeout, CreateConnectionAsync);
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
        HttpConnection connection = await _pool.RentAsync(endpoint, MaxConnectionsPerServer, ct);

        try
        {
            bool viaProxy = ProxyConnection.TryResolveProxy(uri, UseProxy, Proxy, out _);
            byte[] head = HttpRequestSerializer.BuildRequestHead(
                request, uri, body, viaProxy, AutomaticDecompression, UseCookies, CookieContainer);

            await connection.Stream.WriteAsync(head, ct);
            if (body is not null)
            {
                // Written separately: BufferedStream coalesces it with the head for small bodies, and we
                // avoid copying a large request body into a combined buffer.
                await connection.Stream.WriteAsync(body, ct);
            }

            HttpResponse parsed = await _httpResponseParser.Parse(connection.Stream, ct);

            // Return connection to the pool before cookie/decompression mapping; content is buffered anyway.
            connection.IsReusable = IsConnectionReusable(parsed);

            ResponseMapper.AddCookies(parsed, uri, UseCookies, CookieContainer);

            if (AutomaticDecompression != DecompressionMethods.None)
            {
                parsed = ResponseMapper.Decompress(parsed, AutomaticDecompression);
            }

            return ResponseMapper.Build(request, parsed);
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

    private async Task<HttpConnection> CreateConnectionAsync(Endpoint endpoint, CancellationToken ct)
    {
        CancellationToken connectCt = WithConnectTimeout(ct);
        var destination = new Uri($"{endpoint.Scheme}://{endpoint.Host}:{endpoint.Port}/");
        TcpClient client;

        if (!ProxyConnection.TryResolveProxy(destination, UseProxy, Proxy, out Uri? proxyAddress))
        {
            client = new TcpClient();
            await client.ConnectAsync(endpoint.Host, endpoint.Port, connectCt);
        }
        else
        {
            ICredentials? credentials = DefaultProxyCredentials ?? Proxy?.Credentials;
            client = await ProxyConnection.ConnectThroughProxyAsync(endpoint, proxyAddress!, credentials, connectCt);
        }

        Stream stream = client.GetStream();
        if (endpoint.Scheme == Uri.UriSchemeHttps)
        {
            _tlsClient.SetServerName(endpoint.Host);

            var protocol = new TlsClientProtocol(stream);
            protocol.Connect(_tlsClient);
            stream = protocol.Stream;
        }

        return new HttpConnection(client, stream, isTls: endpoint.Scheme == Uri.UriSchemeHttps, endpoint.Host);
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
            HttpHeaders.GetHeader(parsed.Headers, "Content-Length") is not null ||
            HttpHeaders.GetHeader(parsed.Headers, "Transfer-Encoding") is not null;

        if (!knownFraming)
        {
            return false;
        }

        string? connection = HttpHeaders.GetHeader(parsed.Headers, "Connection");
        if (connection?.Contains("close", StringComparison.OrdinalIgnoreCase) == true)
        {
            return false;
        }

        return true;
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
