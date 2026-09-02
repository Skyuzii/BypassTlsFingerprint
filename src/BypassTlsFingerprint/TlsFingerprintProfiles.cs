using Org.BouncyCastle.Tls;

namespace BypassTlsFingerprint;

public static class TlsFingerprintProfiles
{
    public static class Mozilla
    {
        public static readonly TlsFingerprint Firefox0 = new TlsFingerprintBuilder()
            .WithVersions(TlsVersions.Tls10, TlsVersions.Tls11, TlsVersions.Tls12)
            .WithCipherSuites(49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53)
            .AddExtension(ExtensionType.server_name, Array.Empty<byte>())
            .AddExtension(ExtensionType.extended_master_secret, Array.Empty<byte>())
            .AddExtension(ExtensionType.renegotiation_info, new byte[] { 0 })
            .AddExtension(ExtensionType.supported_groups, new byte[] { 0, 8, 0, 29, 0, 23, 0, 24, 0, 25 })
            .AddExtension(ExtensionType.ec_point_formats, new byte[] { 1, 0 })
            .AddExtension(ExtensionType.session_ticket, Array.Empty<byte>())
            .AddExtension(ExtensionType.application_layer_protocol_negotiation, new byte[] { 0, 9, 8, 104, 116, 116, 112, 47, 49, 46, 49 })
            .AddExtension(ExtensionType.status_request, new byte[] { 1, 0, 0, 0, 0 })
            .AddExtension(ExtensionType.signature_algorithms, new byte[] { 0, 22, 4, 3, 5, 3, 6, 3, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 2, 3, 2, 1 })
            .AddExtension(ExtensionType.record_size_limit, new byte[] { 64, 0 })
            .Build();
    }
}
