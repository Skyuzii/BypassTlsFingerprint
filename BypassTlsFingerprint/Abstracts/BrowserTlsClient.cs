using BypassTlsFingerprint.TlsAuthentications;

using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace BypassTlsFingerprint.Abstracts;

public abstract class BrowserTlsClient : DefaultTlsClient
{
    protected BrowserTlsClient(TlsCrypto crypto) : base(crypto)
    {
    }

    public abstract void SetServerName(string host);

    public override TlsAuthentication GetAuthentication()
    {
        return new DefaultTlsAuthentication();
    }
}