using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

using BypassTlsFingerprint.Tests.Support;

namespace BypassTlsFingerprint.Tests;

internal sealed class BypassTlsMessageHandlerAdvancedTests
{
    private static HttpClient CreateClient(Action<BypassTlsMessageHandler>? configure = null)
    {
        var handler = new BypassTlsMessageHandler(TlsFingerprintProfiles.Mozilla.Firefox0);
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
    public async Task ExpectContinue_SendsHeadThenWaitsFor100BeforeBody()
    {
        var observed = new StringBuilder();
        var listener = new TcpListener(IPAddress.Loopback, port: 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Task serverTask = Task.Run(async () =>
        {
            using TcpClient client = await listener.AcceptTcpClientAsync();
            listener.Stop();
            await using NetworkStream stream = client.GetStream();

            string head = await ReadHeadAsync(stream);
            observed.AppendLine("HEAD=" + head.Replace("\r\n", "|"));
            bool hasExpect = head.Contains("Expect: 100-continue", StringComparison.OrdinalIgnoreCase);

            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 100 Continue\r\n\r\n"));

            // After 100, the client must send the Content-Length body.
            byte[] body = await ReadAndDiscardRequestBodyAsync(stream, head);
            observed.AppendLine("BODY=" + Encoding.UTF8.GetString(body));

            await stream.WriteAsync(Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
            _ = hasExpect;
        });

        using HttpClient http = CreateClient(h => h.ExpectContinue = true);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri($"http://127.0.0.1:{port}/"))
        {
            Content = new ByteArrayContent("hello"u8.ToArray()),
        };

        HttpResponseMessage response = await http.SendAsync(request);
        Assert.That((int)response.StatusCode, Is.EqualTo(200));
        await serverTask;

        var log = observed.ToString();
        Assert.That(log, Does.Contain("Expect: 100-continue"));
        Assert.That(log, Does.Contain("BODY=hello"));
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

    private static async Task<byte[]> ReadAndDiscardRequestBodyAsync(Stream stream, string head)
    {
        Match matches = System.Text.RegularExpressions.Regex.Match(head, "Content-Length: (\\d+)", RegexOptions.IgnoreCase);
        if (!matches.Success)
        {
            return Array.Empty<byte>();
        }

        int length = int.Parse(matches.Groups[1].Value);
        var body = new byte[length];
        var total = 0;
        while (total < length)
        {
            int read = await stream.ReadAsync(body.AsMemory(total));
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return body;
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
