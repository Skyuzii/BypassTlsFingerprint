using BypassTlsFingerprint.Abstractions;
using BypassTlsFingerprint.Implementations.TlsClients;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace BypassTlsFingerprint.Implementations;

public sealed class BypassHttpClientFactory
{
    public BypassHttpClient GetHttpClient(string tlsClientName = nameof(MozilaTlsClient))
    {
        TlsCrypto tlsCrypto = GetTlsCrypto();
        BrowserTlsClient tlsClient = GetTlsClientByName(tlsClientName, tlsCrypto);

        return new BypassHttpClient(tlsClient);
    }

    private BrowserTlsClient GetTlsClientByName(string name, TlsCrypto tlsCrypto)
    {
        return name switch
        {
            nameof(MozilaTlsClient) => new MozilaTlsClient(tlsCrypto),
            _ => throw new ArgumentOutOfRangeException(nameof(name), name, message: null)
        };
    }

    private TlsCrypto GetTlsCrypto()
    {
        return new BcTlsCrypto(new SecureRandom());
    }
}