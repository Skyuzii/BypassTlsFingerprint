namespace BypassTlsFingerprint;

/// <summary>A parsed raw HTTP/1.1 response (status line, headers and a buffered binary body).</summary>
internal sealed class HttpResponse
{
    /// <summary>Raw status-line token, e.g. <c>HTTP/1.1</c>.</summary>
    public required string HttpVersion { get; init; }

    public required int StatusCode { get; init; }

    /// <summary>The raw (still encoded) response body. It is buffered, so binary content is preserved.</summary>
    public byte[] Content { get; init; } = Array.Empty<byte>();

    /// <summary>Header values in wire order; a name may appear multiple times (e.g. several <c>Set-Cookie</c>).</summary>
    public List<KeyValuePair<string, string>> Headers { get; init; } = new List<KeyValuePair<string, string>>();

    /// <summary>
    /// Whether the underlying connection can be returned to the pool after this response, based on its
    /// framing and <c>Connection</c> header. Computed once at parse time; the transport trusts it.
    /// </summary>
    public bool IsConnectionReusable { get; init; }
}
