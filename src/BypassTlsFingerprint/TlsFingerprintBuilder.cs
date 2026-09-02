using Org.BouncyCastle.Tls;

namespace BypassTlsFingerprint;

public sealed class TlsFingerprintBuilder
{
    private ProtocolVersion[] _versions = Array.Empty<ProtocolVersion>();
    private int[] _ciphers = Array.Empty<int>();
    private string? _alpn;
    private readonly List<KeyValuePair<int, byte[]>> _extensions = new List<KeyValuePair<int, byte[]>>();

    public TlsFingerprintBuilder WithVersions(params ProtocolVersion[] versions)
    {
        _versions = versions;
        return this;
    }

    public TlsFingerprintBuilder WithCipherSuites(params int[] ciphers)
    {
        _ciphers = ciphers;
        return this;
    }

    /// <summary>Sets the cipher list from a JA3-style decimal, comma-separated string.</summary>
    public TlsFingerprintBuilder WithCiphers(string ja3CipherList)
    {
        if (string.IsNullOrWhiteSpace(ja3CipherList))
        {
            throw new ArgumentException("Cipher list must not be empty.", nameof(ja3CipherList));
        }

        string[] parts = ja3CipherList.Split(separator: ',', StringSplitOptions.TrimEntries);
        var ciphers = new int[parts.Length];
        for (var i = 0; i < parts.Length; i++)
        {
            if (!int.TryParse(parts[i], out int value))
            {
                throw new ArgumentException($"'{parts[i]}' is not a valid JA3 cipher code point.", nameof(ja3CipherList));
            }

            ciphers[i] = value;
        }

        return WithCipherSuites(ciphers);
    }

    public TlsFingerprintBuilder WithAlpn(string alpn)
    {
        _alpn = alpn;
        return this;
    }

    /// <summary>Adds an extension. The call order is the wire order in the ClientHello.</summary>
    public TlsFingerprintBuilder AddExtension(int extensionType, byte[] data)
    {
        _extensions.Add(new KeyValuePair<int, byte[]>(extensionType, data));
        return this;
    }

    public TlsFingerprint Build()
    {
        if (_versions.Length == 0)
        {
            throw new InvalidOperationException("At least one TLS version is required (call WithVersions).");
        }

        if (_ciphers.Length == 0)
        {
            throw new InvalidOperationException("At least one cipher suite is required (call WithCipherSuites).");
        }

        if (string.IsNullOrWhiteSpace(_alpn))
        {
            throw new InvalidOperationException("An ALPN protocol is required (call WithAlpn).");
        }

        List<KeyValuePair<int, byte[]>> extensions = _extensions.ToList();
        if (extensions.All(e => e.Key != ExtensionType.server_name))
        {
            extensions.Insert(index: 0, new KeyValuePair<int, byte[]>(ExtensionType.server_name, Array.Empty<byte>()));
        }

        return new TlsFingerprint
        {
            SupportedVersions = _versions,
            CipherSuites = _ciphers,
            AlpnProtocol = _alpn,
            Extensions = extensions,
        };
    }
}
