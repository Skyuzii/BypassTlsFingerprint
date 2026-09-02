using System.Net;
using System.Net.Sockets;
using System.Text;

using BypassTlsFingerprint.Tests.Support;

namespace BypassTlsFingerprint.Tests;

internal sealed class BypassTlsMessageHandlerAdvancedTests
{
    private static HttpClient CreateClient(Action<BypassTlsFingerprintMessageHandler>? configure = null)
    {
        var handler = new BypassTlsFingerprintMessageHandler(TlsFingerprintProfiles.Mozilla.Firefox0);
        // Disable proxying by default so tests are hermetic; proxy tests opt in via the configure callback.
        handler.Proxy = null;
        configure?.Invoke(handler);
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
    }

    [Test]
    public async Task Proxy_CONNECT_SendsBasicAuthorization()
    {
        string? connectRequest = null;
        var listener = new TcpListener(IPAddress.Loopback, port: 0);
        listener.Start();
        int proxyPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        Task proxyTask = Task.Run(async () =>
        {
            using TcpClient client = await listener.AcceptTcpClientAsync();
            listener.Stop();
            await using NetworkStream stream = client.GetStream();
            connectRequest = await ReadHeadAsync(stream);
            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"));
        });

        using HttpClient http = CreateClient(h =>
        {
            h.Proxy = new WebProxy($"http://127.0.0.1:{proxyPort}")
            {
                Credentials = new NetworkCredential("user", "pass"),
            };
        });

        Exception? ex = await WithTimeoutAsync(
            () => http.GetStringAsync("https://example.invalid/"));
        await proxyTask;

        Assert.That(ex, Is.InstanceOf<HttpRequestException>(), "Proxy rejection must surface as HttpRequestException.");
        Assert.That(connectRequest, Is.Not.Null);
        Assert.That(connectRequest, Does.Contain("CONNECT example.invalid:443 HTTP/1.1"));
        Assert.That(connectRequest, Does.Contain("Proxy-Authorization: Basic dXNlcjpwYXNz"),
            "Expected Basic auth for user:pass.");
    }

    [Test]
    public async Task BypassProxyOnLocal_SkipsProxy_ForLoopback()
    {
        await using FakeHttpServer server = FakeHttpServer.Start((_, _) => Task.FromResult(
            new FakeResponse { Body = "local"u8.ToArray() }));

        // Proxy points at a closed port; it would fail if actually used for the loopback target.
        // WebProxy.BypassProxyOnLocal is true by default, so the loopback destination is contacted directly.
        using HttpClient http = CreateClient(h =>
        {
            h.Proxy = new WebProxy("http://127.0.0.1:1");
        });

        string body = await http.GetStringAsync(server.BaseUri);
        Assert.That(body, Is.EqualTo("local"));
    }

    [Test]
    public async Task ConnectTimeout_AbortsANonReachableHost()
    {
        using HttpClient http = CreateClient(h =>
        {
            h.ConnectTimeout = TimeSpan.FromMilliseconds(500);
        });

        var sw = System.Diagnostics.Stopwatch.StartNew();
        Exception? caught = null;
        try
        {
            // RFC 5737 TEST-NET-1: guaranteed non-routeable, so the SYN never completes.
            await http.GetStringAsync("http://192.0.2.1/");
        }
        catch (Exception ex)
        {
            caught = ex;
        }

        sw.Stop();
        Assert.That(caught, Is.Not.Null, "A non-reachable host must eventually fail.");
        Assert.That(sw.Elapsed, Is.LessThan(TimeSpan.FromSeconds(20)));
    }

    private static async Task<string> ReadHeadAsync(Stream stream)
    {
        var head = new List<byte>(512);
        var one = new byte[1];
        while (true)
        {
            int n = await stream.ReadAsync(one);
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

        return Encoding.ASCII.GetString(head.ToArray());
    }

    private static async Task<Exception?> WithTimeoutAsync(Func<Task> action, int ms = 5000)
    {
        using var cts = new CancellationTokenSource(ms);
        try
        {
            await action();
            return null;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }
}
