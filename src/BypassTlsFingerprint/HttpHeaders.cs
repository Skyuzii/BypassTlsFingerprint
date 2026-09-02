using System.Collections.Frozen;

namespace BypassTlsFingerprint;

/// <summary>Shared, tiny helpers for the repeated HTTP header conventions of the transport.</summary>
internal static class HttpHeaders
{
    /// <summary>
    /// RFC 7230 entity (content) headers. Used to route a parsed header to either the response's
    /// <see cref="HttpContent.Headers"/> or its <see cref="HttpResponseMessage.Headers"/>.
    /// </summary>
    private static readonly FrozenSet<string> ContentHeaders = FrozenSet.Create(
        StringComparer.OrdinalIgnoreCase,
        "Allow", "Content-Disposition", "Content-Encoding", "Content-Language",
        "Content-Length", "Content-Location", "Content-MD5", "Content-Range",
        "Content-Type", "Expires", "Last-Modified");

    public static bool IsContentHeader(string name)
    {
        return ContentHeaders.Contains(name);
    }

    public static string? GetHeader(IReadOnlyList<KeyValuePair<string, string>> headers, string name)
    {
        foreach (KeyValuePair<string, string> header in headers)
        {
            if (string.Equals(header.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                return header.Value;
            }
        }

        return null;
    }
}
