namespace BypassTlsFingerprint.Tests.Support;

/// <summary>A canned response that the <see cref="FakeHttpServer"/> writes to the wire.</summary>
public sealed class FakeResponse
{
    public string StatusLine { get; init; } = "HTTP/1.1 200 OK";

    public List<KeyValuePair<string, string>> Headers { get; } = new List<KeyValuePair<string, string>>();

    public byte[] Body { get; init; } = Array.Empty<byte>();

    /// <summary>When true, the body is written chunked and the <c>Transfer-Encoding</c> header is set.</summary>
    public bool Chunked { get; init; }

    /// <summary>When true, a <c>Connection: close</c> header is added and the socket is closed after.</summary>
    public bool CloseConnection { get; init; }

    public FakeResponse WithHeader(string name, string value)
    {
        Headers.Add(new KeyValuePair<string, string>(name, value));
        return this;
    }
}
