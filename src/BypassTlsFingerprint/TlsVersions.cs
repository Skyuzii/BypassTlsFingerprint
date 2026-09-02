using Org.BouncyCastle.Tls;

namespace BypassTlsFingerprint;

/// <summary>
/// Convenient, discoverable TLS protocol-version constants for use with
/// <see cref="TlsFingerprintBuilder.WithVersions"/>.
/// </summary>
public static class TlsVersions
{
    public static readonly ProtocolVersion Tls10 = ProtocolVersion.TLSv10;
    public static readonly ProtocolVersion Tls11 = ProtocolVersion.TLSv11;
    public static readonly ProtocolVersion Tls12 = ProtocolVersion.TLSv12;
    public static readonly ProtocolVersion Tls13 = ProtocolVersion.TLSv13;
}
