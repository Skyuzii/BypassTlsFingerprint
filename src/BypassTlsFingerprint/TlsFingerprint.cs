using Org.BouncyCastle.Tls;

namespace BypassTlsFingerprint;

public sealed class TlsFingerprint
{
    /// <summary>
    /// TLS versions the ClientHello advertises, in preference order (JA3/JA4 "version")
    /// </summary>
    public required IReadOnlyList<ProtocolVersion> SupportedVersions { get; init; }

    /// <summary>
    /// Cipher suites, in exact ClientHello order (order and count are part of both JA3 and JA4).
    /// GREASE values, if any, are plain numbers here just like real suites.
    /// </summary>
    public required IReadOnlyList<int> CipherSuites { get; init; }

    /// <summary>
    /// The ClientHello extensions in their exact wire order — extension order is significant for
    /// both JA3 and JA4, and the per-extension payloads (e.g. signature_algorithms, supported_groups)
    /// are the raw bytes recorded here. The <see cref="ExtensionType.server_name"/> entry is present
    /// but its value is a placeholder: the real bytes are substituted from the host during the handshake.
    /// </summary>
    public required IReadOnlyList<KeyValuePair<int, byte[]>> Extensions { get; init; }
}
