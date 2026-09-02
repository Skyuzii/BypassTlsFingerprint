using Org.BouncyCastle.Tls;

namespace BypassTlsFingerprint;

public static class TlsFingerprints
{
    public static class Mozilla
    {
        public static readonly TlsFingerprint Firefox0 = new TlsFingerprintBuilder()
            .WithVersions(TlsVersions.Tls10, TlsVersions.Tls11, TlsVersions.Tls12)
            .WithCipherSuites(49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161, 49171, 49172, 156, 157, 47, 53)
            .AddExtension(ExtensionType.server_name, [])
            .AddExtension(ExtensionType.extended_master_secret, [])
            .AddExtension(ExtensionType.renegotiation_info, [0])
            .AddExtension(ExtensionType.supported_groups, [0, 8, 0, 29, 0, 23, 0, 24, 0, 25])
            .AddExtension(ExtensionType.ec_point_formats, [1, 0])
            .AddExtension(ExtensionType.session_ticket, [])
            .AddExtension(ExtensionType.application_layer_protocol_negotiation, [0, 9, 8, 104, 116, 116, 112, 47, 49, 46, 49])
            .AddExtension(ExtensionType.status_request, [1, 0, 0, 0, 0])
            .AddExtension(ExtensionType.signature_algorithms, [0, 22, 4, 3, 5, 3, 6, 3, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 2, 3, 2, 1])
            .AddExtension(ExtensionType.record_size_limit, [64, 0])
            .Build();
    }
}
