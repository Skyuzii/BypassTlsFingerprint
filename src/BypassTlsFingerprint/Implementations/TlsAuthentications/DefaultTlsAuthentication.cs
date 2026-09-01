using Org.BouncyCastle.Tls;

namespace BypassTlsFingerprint.Implementations.TlsAuthentications;

internal sealed class DefaultTlsAuthentication : TlsAuthentication
{
    public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
    {
    }

    public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest)
    {
        return null;
    }
}