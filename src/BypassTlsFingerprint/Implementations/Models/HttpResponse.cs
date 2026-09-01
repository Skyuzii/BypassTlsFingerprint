using System.Net;

namespace BypassTlsFingerprint.Implementations.Models;

public sealed class HttpResponse
{
    public string HttpVersion { get; set; }

    public int StatusCode { get; set; }

    public string? Content { get; set; }

    public CookieCollection Cookies { get; set; } = new CookieCollection();

    public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
}