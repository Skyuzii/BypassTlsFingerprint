using BypassTlsFingerprint.Abstractions;
using BypassTlsFingerprint.Implementations.TlsClients;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace BypassTlsFingerprint.Implementations;

public sealed class BypassTlsMessageHandlerFactory
{
    public BypassTlsMessageHandler GetMessageHandler(string tlsClientName = BypassTlsClientNames.Mozila)
    {
        TlsCrypto tlsCrypto = new BcTlsCrypto(new SecureRandom());
        BrowserTlsClient tlsClient = GetTlsClientByName(tlsClientName, tlsCrypto);

        return new BypassTlsMessageHandler(tlsClient);
    }

    private static BrowserTlsClient GetTlsClientByName(string name, TlsCrypto tlsCrypto)
    {
        return name switch
        {
            nameof(MozilaTlsClient) => new MozilaTlsClient(tlsCrypto),
            _ => throw new ArgumentOutOfRangeException(nameof(name), name, message: null)
        };
    }
}
