using System.Text;

using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace BypassTlsFingerprint;

internal sealed class CustomTlsClient : DefaultTlsClient
{
    private readonly TlsFingerprint _fingerprint;
    private readonly IDictionary<int, byte[]> _clientExtensions;

    internal CustomTlsClient(TlsCrypto crypto, TlsFingerprint fingerprint) : base(crypto)
    {
        _fingerprint = fingerprint;

        var extensions = new Dictionary<int, byte[]>();
        foreach (KeyValuePair<int, byte[]> extension in fingerprint.Extensions)
        {
            extensions[extension.Key] = extension.Value;
        }

        if (!extensions.ContainsKey(ExtensionType.application_layer_protocol_negotiation) && !string.IsNullOrEmpty(fingerprint.AlpnProtocol))
        {
            extensions[ExtensionType.application_layer_protocol_negotiation] = BuildAlpnExtensionBody(fingerprint.AlpnProtocol);
        }

        _clientExtensions = extensions;
    }

    public void SetServerName(string host)
    {
        byte[] name = Encoding.ASCII.GetBytes(host);
        var ext = new byte[5 + name.Length];
        ext[0] = 0;
        ext[1] = (byte) (3 + name.Length);
        ext[2] = 0;
        ext[3] = 0;
        ext[4] = (byte) name.Length;
        for (int i = 5, j = 0; i < ext.Length; i++, j++)
        {
            ext[i] = name[j];
        }

        _clientExtensions[ExtensionType.server_name] = ext;
    }

    protected override ProtocolVersion[] GetSupportedVersions()
    {
        return _fingerprint.SupportedVersions;
    }

    public override int[] GetCipherSuites()
    {
        return _fingerprint.CipherSuites;
    }

    public override IDictionary<int, byte[]> GetClientExtensions()
    {
        if (!_clientExtensions.TryGetValue(ExtensionType.server_name, out byte[]? serverName) || serverName.Length == 0)
        {
            throw new ArgumentNullException("ServerName", "ServerName must be set");
        }

        return _clientExtensions;
    }

    public override TlsAuthentication GetAuthentication()
    {
        return new DefaultTlsAuthentication();
    }

    private static byte[] BuildAlpnExtensionBody(string protocol)
    {
        byte[] name = Encoding.ASCII.GetBytes(protocol);
        var body = new byte[3 + name.Length];
        body[0] = 0;
        body[1] = (byte)(1 + name.Length);
        body[2] = (byte)name.Length;
        Array.Copy(name, sourceIndex: 0, body, destinationIndex: 3, name.Length);
        return body;
    }
}
