using BypassTlsFingerprint.Abstracts;
using BypassTlsFingerprint.Helpers;

using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace BypassTlsFingerprint.TlsClients;

internal sealed class MozilaTlsClient : BrowserTlsClient
{
    private IDictionary<int, byte[]> _clientExtensions = new Dictionary<int, byte[]>();

    public MozilaTlsClient(TlsCrypto crypto) : base(crypto)
    {
        InitClientExtensions();
    }

    public MozilaTlsClient(TlsCrypto crypto, string host) : base(crypto)
    {
        InitClientExtensions();
        SetServerName(host);
    }

    protected override ProtocolVersion[] GetSupportedVersions()
    {
        return new[]
        {
            ProtocolVersion.TLSv10,
            ProtocolVersion.TLSv11,
            ProtocolVersion.TLSv12
        };
    }

    public override int[] GetCipherSuites()
    {
        return new int[14]
        {
            49195,
            49199,
            52393,
            52392,
            49196,
            49200,
            49162,
            49161,
            49171,
            49172,
            156,
            157,
            47,
            53
        };
    }

    public override IDictionary<int, byte[]> GetClientExtensions()
    {
        if (_clientExtensions[ExtensionType.server_name].Length == 0)
        {
            throw new ArgumentNullException("ServerName", "ServerName должен быть заполнен");
        }

        return _clientExtensions;
    }

    public override void SetServerName(string host)
    {
        _clientExtensions[ExtensionType.server_name] = TlsExtensionHelper.GetServerNameExtension(host);
    }

    private byte[] GetRecordSizeLimit()
    {
        return new byte[2] { 64, 0 };
    }

    private byte[] GetSignatureAlgorithms()
    {
        return new byte[24] { 0, 22, 4, 3, 5, 3, 6, 3, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 2, 3, 2, 1 };
    }

    private byte[] GetStatusRequest()
    {
        return new byte[5] { 1, 0, 0, 0, 0 };
    }

    private byte[] GetEcPointFormats()
    {
        return new byte[2] { 1, 0 };
    }

    private byte[] GetApplicationLayerProtocolNegotiation()
    {
        return new byte[14] { 0, 12, 2, 104, 50, 8, 104, 116, 116, 112, 47, 49, 46, 49 };
    }

    private byte[] GetRenegotiationInfo()
    {
        return new byte[1] { 0 };
    }

    private byte[] GetExtendedMasterSecret()
    {
        return Array.Empty<byte>();
    }

    private byte[] GetSupportedGroups()
    {
        return new byte[10] { 0, 8, 0, 29, 0, 23, 0, 24, 0, 25 };
    }

    private byte[] GetSessionTicket()
    {
        return Array.Empty<byte>();
    }

    private void InitClientExtensions()
    {
        _clientExtensions = new Dictionary<int, byte[]>();

        // важно сохранить именно такую последовательность
        _clientExtensions.Add(ExtensionType.server_name, Array.Empty<byte>());
        _clientExtensions.Add(ExtensionType.extended_master_secret, GetExtendedMasterSecret());
        _clientExtensions.Add(ExtensionType.renegotiation_info, GetRenegotiationInfo());
        _clientExtensions.Add(ExtensionType.supported_groups, GetSupportedGroups());
        _clientExtensions.Add(ExtensionType.ec_point_formats, GetEcPointFormats());
        _clientExtensions.Add(ExtensionType.session_ticket, GetSessionTicket());
        _clientExtensions.Add(ExtensionType.application_layer_protocol_negotiation, GetApplicationLayerProtocolNegotiation());
        _clientExtensions.Add(ExtensionType.status_request, GetStatusRequest());
        _clientExtensions.Add(ExtensionType.signature_algorithms, GetSignatureAlgorithms());
        _clientExtensions.Add(ExtensionType.record_size_limit, GetRecordSizeLimit());
    }
}
