using BypassTlsFingerprint.Abstracts;
using BypassTlsFingerprint.TlsClients;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace BypassTlsFingerprint;

public sealed class BypassHttpClientFactory
{
    public BypassHttpClient GetHttpClient(string tlsClientName = nameof(MozilaTlsClient))
    {
        var tlsCrypto = GetTlsCrypto();
        var tlsClient = GetTlsClientByName(tlsClientName, tlsCrypto);

        return new BypassHttpClient(tlsClient);
    }

    private BrowserTlsClient GetTlsClientByName(string name, TlsCrypto tlsCrypto)
    {
        return name switch
        {
            nameof(MozilaTlsClient) => new MozilaTlsClient(tlsCrypto),
            _ => throw new ArgumentOutOfRangeException(nameof(name), name, null)
        };
    }

    private TlsCrypto GetTlsCrypto()
    {
        return new BcTlsCrypto(new SecureRandom());
    }
}