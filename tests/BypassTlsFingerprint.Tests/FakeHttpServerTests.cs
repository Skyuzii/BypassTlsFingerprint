using BypassTlsFingerprint.Tests.Support;

namespace BypassTlsFingerprint.Tests;

internal sealed class FakeHttpServerTests
{
    [Test]
    public async Task Get_Plaintext_ReturnsBody()
    {
        await using FakeHttpServer server = FakeHttpServer.Start((_, _) => Task.FromResult(
            new FakeResponse
            {
                Body = "hello world"u8.ToArray(),
            }.WithHeader("Content-Type", "text/plain")));

        using var client = new HttpClient();
        string body = await client.GetStringAsync(server.BaseUri);
        Assert.That(body, Is.EqualTo("hello world"));
    }

    [Test]
    public async Task TwoRequests_AreReusedOnOneSocket()
    {
        var seen = 0;
        await using FakeHttpServer server = FakeHttpServer.Start((_, _) =>
        {
            Interlocked.Increment(ref seen);
            return Task.FromResult(new FakeResponse { Body = "ok"u8.ToArray() });
        });

        using var client = new HttpClient();
        _ = await client.GetStringAsync(server.BaseUri);
        _ = await client.GetStringAsync(server.BaseUri);

        Assert.That(seen, Is.EqualTo(2));
        Assert.That(server.ConnectionCount, Is.EqualTo(1), "Both requests should reuse a single connection.");
    }
}
