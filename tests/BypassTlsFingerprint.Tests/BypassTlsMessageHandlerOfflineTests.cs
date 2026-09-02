using System.IO.Compression;
using System.Net;
using System.Text;

using BypassTlsFingerprint.Tests.Support;

namespace BypassTlsFingerprint.Tests;

internal sealed class BypassTlsMessageHandlerOfflineTests
{
    private static HttpClient CreateClient(Action<BypassTlsFingerprintMessageHandler>? configure = null)
    {
        var handler = new BypassTlsFingerprintMessageHandler(TlsFingerprints.Mozilla.Firefox0);
        handler.Proxy = null;
        configure?.Invoke(handler);
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
    }

    [Test]
    public async Task Get_Plaintext_ReturnsBody()
    {
        await using FakeHttpServer server = FakeHttpServer.Start((_, _) => Task.FromResult(
            new FakeResponse { Body = "plain hello"u8.ToArray() }));

        using HttpClient client = CreateClient();
        string body = await client.GetStringAsync(server.BaseUri);

        Assert.That(body, Is.EqualTo("plain hello"));
    }

    [Test]
    public async Task Get_ChunkedResponse_IsDecoded()
    {
        await using FakeHttpServer server = FakeHttpServer.Start((_, _) => Task.FromResult(
            new FakeResponse { Body = "chunked body"u8.ToArray(), Chunked = true }));

        using HttpClient client = CreateClient();
        string body = await client.GetStringAsync(server.BaseUri);

        Assert.That(body, Is.EqualTo("chunked body"));
    }

    [Test]
    public async Task Get_Gzip_WithAutomaticDecompression_IsDecompressed()
    {
        byte[] gzipped = await GzipAsync("hello gzip"u8.ToArray());
        await using FakeHttpServer server = FakeHttpServer.Start((_, _) => Task.FromResult(
            new FakeResponse { Body = gzipped }.WithHeader("Content-Encoding", "gzip")));

        using HttpClient client = CreateClient(h => h.AutomaticDecompression = DecompressionMethods.GZip);
        string body = await client.GetStringAsync(server.BaseUri);

        Assert.That(body, Is.EqualTo("hello gzip"));
    }

    [Test]
    public async Task Post_Redirect301_SwitchesToGetAndDropsBody()
    {
        var seen = new List<(string Method, byte[] Body)>();
        await using FakeHttpServer server = FakeHttpServer.Start((req, _) =>
        {
            if (req.Path == "/start")
            {
                return Task.FromResult(new FakeResponse { StatusLine = "HTTP/1.1 301 Moved Permanently" }
                    .WithHeader("Location", "/end"));
            }

            seen.Add((req.Method, req.Body));
            return Task.FromResult(new FakeResponse { Body = "ok"u8.ToArray() });
        });

        using HttpClient httpClient = CreateClient(h => h.AllowAutoRedirect = true);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(server.BaseUri, "/start"))
        {
            Content = new ByteArrayContent("payload"u8.ToArray()),
        };

        HttpResponseMessage response = await httpClient.SendAsync(request);

        Assert.That((int)response.StatusCode, Is.EqualTo(200));
        Assert.That(seen.Single().Method, Is.EqualTo("GET"), "301 must convert POST to GET.");
        Assert.That(seen.Single().Body.Length, Is.EqualTo(0), "GET redirect must drop the request body.");
    }

    [Test]
    public async Task Post_Redirect307_PreservesMethodAndBody()
    {
        var seen = new List<(string Method, byte[] Body)>();
        await using FakeHttpServer server = FakeHttpServer.Start((req, _) =>
        {
            if (req.Path == "/start")
            {
                return Task.FromResult(new FakeResponse { StatusLine = "HTTP/1.1 307 Temporary Redirect" }
                    .WithHeader("Location", "/end"));
            }

            seen.Add((req.Method, req.Body));
            return Task.FromResult(new FakeResponse { Body = "ok"u8.ToArray() });
        });

        using HttpClient httpClient = CreateClient(h => h.AllowAutoRedirect = true);
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(server.BaseUri, "/start"))
        {
            Content = new ByteArrayContent("payload"u8.ToArray()),
        };

        HttpResponseMessage response = await httpClient.SendAsync(request);

        Assert.That((int)response.StatusCode, Is.EqualTo(200));
        Assert.That(seen.Single().Method, Is.EqualTo("POST"), "307 must preserve the method.");
        Assert.That(Encoding.UTF8.GetString(seen.Single().Body), Is.EqualTo("payload"), "307 must preserve the body.");
    }

    [Test]
    public async Task Cookies_AreStoredAndSentOnNextRequest()
    {
        string? cookieSeenOnGet = null;
        await using FakeHttpServer server = FakeHttpServer.Start((req, _) =>
        {
            if (req.Path == "/set")
            {
                return Task.FromResult(new FakeResponse()
                    .WithHeader("Set-Cookie", "sid=abc123; Path=/"));
            }

            cookieSeenOnGet = req.Headers.GetValueOrDefault("Cookie");
            return Task.FromResult(new FakeResponse { Body = "ok"u8.ToArray() });
        });

        using HttpClient httpClient = CreateClient(h => h.CookieContainer = new CookieContainer());

        _ = await httpClient.GetStringAsync(new Uri(server.BaseUri, "/set"));
        _ = await httpClient.GetAsync(new Uri(server.BaseUri, "/get"));

        Assert.That(cookieSeenOnGet, Is.EqualTo("sid=abc123"));
    }

    [Test]
    public async Task SequentialRequests_ReuseSingleKeepAliveConnection()
    {
        var seen = 0;
        await using FakeHttpServer server = FakeHttpServer.Start((req, _) =>
        {
            Interlocked.Increment(ref seen);
            return Task.FromResult(new FakeResponse { Body = "ok"u8.ToArray() });
        });

        using HttpClient httpClient = CreateClient();

        _ = await httpClient.GetStringAsync(server.BaseUri);
        _ = await httpClient.GetStringAsync(server.BaseUri);
        _ = await httpClient.GetStringAsync(server.BaseUri);

        Assert.That(seen, Is.EqualTo(3));
        Assert.That(server.ConnectionCount, Is.EqualTo(1), "Sequential requests should reuse one keep-alive connection.");
        Assert.That(server.ConnectionsByRequestCount, Does.ContainKey(3));
    }

    [Test]
    public async Task ConcurrentRequests_AreServedOverPooledConnections()
    {
        var seen = 0;
        await using FakeHttpServer server = FakeHttpServer.Start((_, _) =>
        {
            Interlocked.Increment(ref seen);
            return Task.FromResult(new FakeResponse { Body = "ok"u8.ToArray() });
        });

        using HttpClient httpClient = CreateClient();
        Task<string>[] tasks = Enumerable.Range(start: 0, count: 8)
            .Select(_ => httpClient.GetStringAsync(server.BaseUri))
            .ToArray();

        string[] bodies = await Task.WhenAll(tasks);

        Assert.That(bodies, Is.EqualTo(Enumerable.Repeat("ok", count: 8)));
        Assert.That(seen, Is.EqualTo(8));
        Assert.That(server.ConnectionCount, Is.LessThanOrEqualTo(8), "Concurrent requests must not leak one connection each beyond the pool.");
    }

    [Test]
    public async Task Get_Https_OverTls_ReturnsBody()
    {
        await using FakeHttpServer server = FakeHttpServer.StartTls((_, _) => Task.FromResult(
            new FakeResponse { Body = "secure hello"u8.ToArray() }));

        using HttpClient client = CreateClient();
        string body = await client.GetStringAsync(server.BaseUri);

        Assert.That(body, Is.EqualTo("secure hello"));
    }

    [Test]
    public async Task Header_WithMultipleValues_IsPreserved()
    {
        await using FakeHttpServer server = FakeHttpServer.Start((_, _) => Task.FromResult(
            new FakeResponse { Body = "ok"u8.ToArray() }
                .WithHeader("Set-Cookie", "a=1")
                .WithHeader("Set-Cookie", "b=2")));

        using HttpClient httpClient = CreateClient(h => h.CookieContainer = new CookieContainer());
        using HttpResponseMessage response = await httpClient.GetAsync(server.BaseUri);

        IEnumerable<string> cookies = response.Headers.GetValues("Set-Cookie");
        Assert.That(cookies, Does.Contain("a=1").And.Contain("b=2"));
    }

    private static async Task<byte[]> GzipAsync(byte[] data)
    {
        using var output = new MemoryStream();
        await using (var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true))
        {
            await gzip.WriteAsync(data);
        }

        return output.ToArray();
    }
}
