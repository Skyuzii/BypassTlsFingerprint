using BypassTlsFingerprint.Tests.Support;

using Org.BouncyCastle.Tls;

namespace BypassTlsFingerprint.Tests;

internal sealed class TlsFingerprintBuilderTests
{
    [Test]
    public async Task CustomFingerprint_ReachesTheClient_AndCompletesHandshake()
    {
        TlsFingerprint fingerprint = new TlsFingerprintBuilder()
            .WithVersions(TlsVersions.Tls12)
            .WithCipherSuites(49195, 49199, 52393, 49196, 49200, 156, 47)
            .WithAlpn("http/1.1")
            .AddExtension(ExtensionType.supported_groups, new byte[] { 0, 8, 0, 29, 0, 23, 0, 24, 0, 25 })
            .AddExtension(ExtensionType.ec_point_formats, new byte[] { 1, 0 })
            .AddExtension(ExtensionType.signature_algorithms, new byte[] { 0, 22, 4, 3, 5, 3, 6, 3, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 2, 3, 2, 1 })
            .AddExtension(ExtensionType.record_size_limit, new byte[] { 64, 0 })
            .Build();

        var handler = new BypassTlsMessageHandler(fingerprint);
        handler.Proxy = null; // keep the test hermetic (offline)

        await using FakeHttpServer server = FakeHttpServer.StartTls((_, _) => Task.FromResult(
            new FakeResponse { Body = "custom fp hello"u8.ToArray() }));

        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        string body = await client.GetStringAsync(server.BaseUri);

        Assert.That(body, Is.EqualTo("custom fp hello"));
    }
}
