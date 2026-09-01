using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace BypassTlsFingerprint.Abstractions;

public abstract class BrowserTlsClient : DefaultTlsClient
{
    protected BrowserTlsClient(TlsCrypto crypto) : base(crypto)
    {
    }

    /// <summary>Sets the SNI/host used by the client. Called before the handshake.</summary>
    public abstract void SetServerName(string host);
}
