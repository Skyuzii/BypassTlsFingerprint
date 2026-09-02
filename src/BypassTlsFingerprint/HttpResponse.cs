namespace BypassTlsFingerprint;

/// <summary>A parsed raw HTTP/1.1 response (status line, headers and a buffered binary body).</summary>
internal sealed class HttpResponse
{
    public string HttpVersion { get; set; } = string.Empty;

    public int StatusCode { get; set; }

    /// <summary>The raw (still encoded) response body. It is buffered, so binary content is preserved.</summary>
    public byte[] Content { get; set; } = Array.Empty<byte>();

    /// <summary>Header values in wire order; a name may appear multiple times (e.g. several <c>Set-Cookie</c>).</summary>
    public List<KeyValuePair<string, string>> Headers { get; } = new List<KeyValuePair<string, string>>();
}
