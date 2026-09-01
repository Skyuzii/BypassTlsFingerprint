using Org.BouncyCastle.Tls;

namespace BypassTlsFingerprint.Implementations;

/// <summary>
/// The default <see cref="TlsAuthentication"/>: accepts any server certificate and sends no client
/// certificate.
/// </summary>
internal sealed class DefaultTlsAuthentication : TlsAuthentication
{
    public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
    {
        // Accept any server certificate.
    }

    public TlsCredentials? GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest certificateRequest)
    {
        // Client certificates are not currently sent.
        return null;
    }
}
