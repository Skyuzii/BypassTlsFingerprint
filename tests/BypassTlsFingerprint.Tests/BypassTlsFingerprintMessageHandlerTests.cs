namespace BypassTlsFingerprint.Tests;

internal sealed class BypassTlsFingerprintMessageHandlerTests
{
    private const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36";

    private static BypassTlsFingerprintMessageHandler CreateHandler(Action<BypassTlsFingerprintMessageHandler>? configure = null)
    {
        var handler = new BypassTlsFingerprintMessageHandler(TlsFingerprints.Mozilla.Firefox0);
        configure?.Invoke(handler);
        return handler;
    }

    [Test]
    public async Task GetString_ShouldReturnContent()
    {
        using var httpClient = new HttpClient(CreateHandler());
        httpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", UserAgent);

        string response = await httpClient.GetStringAsync("https://tls.browserleaks.com/tls");

        Assert.That(response, Is.Not.Null.And.Not.Empty);
    }
}
