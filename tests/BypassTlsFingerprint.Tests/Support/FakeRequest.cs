namespace BypassTlsFingerprint.Tests.Support;

/// <summary>A parsed HTTP/1.1 request received by the <see cref="FakeHttpServer"/>.</summary>
public sealed class FakeRequest
{
    public string Method { get; init; } = "";

    public string Path { get; init; } = "";

    public Dictionary<string, string> Headers { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public byte[] Body { get; init; } = Array.Empty<byte>();

    /// <summary>True when the request carried <c>Connection: close</c>.</summary>
    public bool WantsClose => Headers.TryGetValue("Connection", out string? value) &&
        value?.Contains("close", StringComparison.OrdinalIgnoreCase) == true;
}
