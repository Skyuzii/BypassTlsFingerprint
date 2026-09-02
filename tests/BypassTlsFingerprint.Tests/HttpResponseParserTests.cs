using System.Text;

namespace BypassTlsFingerprint.Tests;

internal sealed class HttpResponseParserTests
{
    [Test]
    public async Task Parse_WithContentLength_ReadsExactlyTheBody()
    {
        byte[] raw = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/html\r\n" +
            "Content-Length: 12\r\n" +
            "\r\n" +
            "0123456789ab");

        using var stream = new MemoryStream(raw);
        HttpResponse result = await new HttpResponseParser().Parse(stream, CancellationToken.None);

        Assert.That(result.HttpVersion, Is.EqualTo("HTTP/1.1"));
        Assert.That(result.StatusCode, Is.EqualTo(200));
        Assert.That(Encoding.UTF8.GetString(result.Content), Is.EqualTo("0123456789ab"));
        Assert.That(result.Headers.Single(h => h.Key == "Content-Type").Value, Is.EqualTo("text/html"));
    }

    [Test]
    public async Task Parse_WithChunkedEncoding_DecodesBody()
    {
        byte[] raw = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Transfer-Encoding: chunked\r\n" +
            "\r\n" +
            "5\r\n" +
            "Hello\r\n" +
            "6\r\n" +
            " World\r\n" +
            "0\r\n" +
            "\r\n");

        using var stream = new MemoryStream(raw);
        HttpResponse result = await new HttpResponseParser().Parse(stream, CancellationToken.None);

        Assert.That(Encoding.UTF8.GetString(result.Content), Is.EqualTo("Hello World"));
    }

    [Test]
    public async Task Parse_WithoutLength_ReadsUntilEof()
    {
        byte[] raw = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Connection: close\r\n" +
            "\r\n" +
            "streamed body");

        using var stream = new MemoryStream(raw);
        HttpResponse result = await new HttpResponseParser().Parse(stream, CancellationToken.None);

        Assert.That(Encoding.UTF8.GetString(result.Content), Is.EqualTo("streamed body"));
    }

    [Test]
    public async Task Parse_WithDuplicateHeaders_KeepsAllValues()
    {
        byte[] raw = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Set-Cookie: a=1\r\n" +
            "Set-Cookie: b=2\r\n" +
            "Content-Length: 2\r\n" +
            "\r\n" +
            "ok");

        using var stream = new MemoryStream(raw);
        HttpResponse result = await new HttpResponseParser().Parse(stream, CancellationToken.None);

        List<string> cookies = result.Headers.Where(h => h.Key == "Set-Cookie").Select(h => h.Value).ToList();
        Assert.That(cookies, Is.EqualTo(new[] { "a=1", "b=2" }));
    }
}
