using System.Net;

namespace BypassTlsFingerprint.Models;

public sealed class HttpResponse
{
    public string HttpVersion { get; set; }

    public int StatusCode { get; set; }

    public string? Content { get; set; }

    public CookieCollection Cookies { get; set; } = new();

    public Dictionary<string, string> Headers { get; set; } = new();
}