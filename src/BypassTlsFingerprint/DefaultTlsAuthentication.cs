using Org.BouncyCastle.Tls;

namespace BypassTlsFingerprint;

/// <summary>
/// The default <see cref="TlsAuthentication"/>: accepts any server certificate and sends no client
/// certificate. Accepting any certificate is intentional — this library exists to impersonate a browser
/// fingerprint, and validating certificates is out of scope (both for strict impersonation and for
/// MITM/interception scenarios). Consumers who need verification must provide their own
/// <see cref="TlsAuthentication"/>.
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
