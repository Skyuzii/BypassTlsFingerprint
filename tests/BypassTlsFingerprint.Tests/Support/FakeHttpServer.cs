using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace BypassTlsFingerprint.Tests.Support;

/// <summary>
/// A minimal HTTP/1.1 test server used to keep integration tests deterministic and offline.
/// Serves canned responses over raw TCP (optionally TLS) and counts the requests received on each
/// connection so keep-alive / pooling behaviour can be asserted. Supports a fake CONNECT proxy mode.
/// </summary>
/// <remarks>
/// Purposely hand-rolled (not <see cref="HttpListener"/>) so we can emit any framing we want:
/// keep-alive, <c>Connection: close</c>, chunked transfer-encoding, gzip/brotli bytes, redirects
/// and a fake CONNECT proxy.
/// </remarks>
public sealed class FakeHttpServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly bool _useTls;
    private readonly bool _proxyMode;
    private readonly Func<FakeRequest, CancellationToken, Task<FakeResponse>> _respond;
    private readonly X509Certificate2? _certificate;
    private readonly ConcurrentDictionary<long, int> _requestsPerSocket = new ConcurrentDictionary<long, int>();
    private readonly ConcurrentBag<TcpClient> _clients = new ConcurrentBag<TcpClient>();
    private readonly CancellationTokenSource _cts = new CancellationTokenSource();
    private readonly Task _acceptLoop;
    private readonly Action<FakeRequest>? _onRequest;
    private long _nextConnectionId;
    private int _connectionCount;

    private FakeHttpServer(
        bool useTls,
        bool proxyMode,
        Action<FakeRequest>? onRequest,
        Func<FakeRequest, CancellationToken, Task<FakeResponse>> respond)
    {
        _useTls = useTls;
        _proxyMode = proxyMode;
        _onRequest = onRequest;
        _respond = respond;
        _listener = new TcpListener(IPAddress.Loopback, port: 0);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Scheme = useTls ? "https" : "http";
        BaseUri = new Uri($"{Scheme}://127.0.0.1:{Port}/");

        if (useTls)
        {
            _certificate = CreateSelfSignedCertificate();
        }

        _acceptLoop = AcceptLoopAsync(_cts.Token);
    }

    /// <summary>Starts a plain HTTP server.</summary>
    public static FakeHttpServer Start(Func<FakeRequest, CancellationToken, Task<FakeResponse>> respond, Action<FakeRequest>? onRequest = null)
    {
        return new FakeHttpServer(useTls: false, proxyMode: false, onRequest, respond);
    }

    /// <summary>Starts a TLS server with a self-signed certificate (client must accept it).</summary>
    public static FakeHttpServer StartTls(Func<FakeRequest, CancellationToken, Task<FakeResponse>> respond, Action<FakeRequest>? onRequest = null)
    {
        return new FakeHttpServer(useTls: true, proxyMode: false, onRequest, respond);
    }

    /// <summary>
    /// Starts a fake CONNECT proxy. It responds <c>200 Connection established</c> and then blindly
    /// relays bytes in both directions.
    /// </summary>
    public static FakeHttpServer StartProxy(Action<FakeRequest>? onRequest = null)
    {
        return new FakeHttpServer(
            useTls: false,
            proxyMode: true,
            onRequest,
            (_, _) => Task.FromResult<FakeResponse>(
                new FakeResponse
                {
                    StatusLine = "HTTP/1.1 200 Connection established",
                }));
    }

    public int Port { get; }

    public string Scheme { get; }

    public Uri BaseUri { get; }

    public int ConnectionCount => Volatile.Read(ref _connectionCount);

    /// <summary>Request count received on each connection, keyed by connection id.</summary>
    public IReadOnlyDictionary<long, int> RequestsPerSocket => _requestsPerSocket;

    /// <summary>Counts of how many connections saw each request count (used to spot pooling).</summary>
    public IReadOnlyDictionary<int, int> ConnectionsByRequestCount => _requestsPerSocket.GroupBy(kv => kv.Value).ToDictionary(g => g.Key, g => g.Count());

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
                break;
            }

            _clients.Add(client);
            long connectionId = Interlocked.Increment(ref _nextConnectionId);
            Interlocked.Increment(ref _connectionCount);
            _requestsPerSocket[connectionId] = 0;
            _ = Task.Run(() => HandleConnectionAsync(client, connectionId, ct), ct);
        }
    }

    private async Task HandleConnectionAsync(TcpClient client, long connectionId, CancellationToken ct)
    {
        Stream stream = client.GetStream();
        if (_useTls)
        {
            var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
            try
            {
                await ssl.AuthenticateAsServerAsync(
                    new SslServerAuthenticationOptions { ServerCertificate = _certificate }, ct);
            }
            catch (Exception)
            {
                return;
            }

            stream = ssl;
        }

        if (_proxyMode)
        {
            // CONNECT proxy: read one CONNECT request, answer, then relay bytes both ways until close.
            FakeRequest connect = await FakeHttp.TryReadRequestAsync(stream, ct) ?? new FakeRequest();
            _requestsPerSocket[connectionId] += 1;
            _onRequest?.Invoke(connect);

            await FakeHttp.WriteRawAsync(stream, "HTTP/1.1 200 Connection established\r\n\r\n", ct);

            // Relay is only necessary when the client actually tunnels TLS through the proxy; for tests
            // that only assert the CONNECT line we can leave the connection open and let it be torn down.
            await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
            return;
        }

        while (!ct.IsCancellationRequested)
        {
            FakeRequest? request = await FakeHttp.TryReadRequestAsync(stream, ct);
            if (request is null)
            {
                break;
            }

            _requestsPerSocket[connectionId] += 1;
            _onRequest?.Invoke(request);

            FakeResponse response;
            try
            {
                response = await _respond(request, ct);
            }
            catch (Exception)
            {
                break;
            }

            if (response.Chunked)
            {
                await FakeHttp.WriteChunkedResponseAsync(stream, response.StatusLine, response.Headers, response.Body, chunkSize: 4, ct);
            }
            else
            {
                await FakeHttp.WriteResponseAsync(stream, response, ct);
            }

            if (response.CloseConnection || request.WantsClose)
            {
                break;
            }
        }

        try
        {
            client.Dispose();
        }
        catch (Exception)
        {
            // best effort
        }
    }

    private static X509Certificate2 CreateSelfSignedCertificate()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: false));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: false));

        return req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(365));
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _listener.Stop();
        foreach (TcpClient client in _clients)
        {
            try
            {
                client.Dispose();
            }
            catch (Exception)
            {
                // best effort
            }
        }

        try
        {
            await _acceptLoop;
        }
        catch (Exception)
        {
            // shutting down
        }

        _cts.Dispose();
        _certificate?.Dispose();
    }
}
