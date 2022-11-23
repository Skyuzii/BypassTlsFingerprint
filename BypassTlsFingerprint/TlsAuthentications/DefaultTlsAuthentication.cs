using Org.BouncyCastle.Tls;

namespace BypassTlsFingerprint.TlsAuthentications;

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