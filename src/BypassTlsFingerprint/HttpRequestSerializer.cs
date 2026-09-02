using System.Net;
using System.Text;

namespace BypassTlsFingerprint;

/// <summary>Serializes the outbound HTTP/1.1 request head (request line + headers). The body is written
/// separately by the caller so a full request body is never copied into a combined buffer.</summary>
internal static class HttpRequestSerializer
{
    public static byte[] BuildRequestHead(
        HttpRequestMessage request,
        Uri uri,
        byte[]? body,
        bool viaProxy,
        DecompressionMethods automaticDecompression,
        bool useCookies,
        CookieContainer? cookieContainer)
    {
        bool absoluteForm = viaProxy && uri.Scheme == Uri.UriSchemeHttp;
        string target = BuildRequestTarget(request, uri, absoluteForm);

        // HTTP/1.1 mandates CRLF line endings — never Environment.NewLine (which is "\\n" on Unix).
        var sb = new StringBuilder();
        sb.Append(request.Method).Append(' ').Append(target).Append(" HTTP/1.1\r\n");
        sb.Append("Host: ").Append(request.Headers.Host ?? uri.Host).Append("\r\n");

        if (automaticDecompression != DecompressionMethods.None)
        {
            sb.Append("Accept-Encoding: ").Append(BuildAcceptEncoding(automaticDecompression)).Append("\r\n");
        }

        foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers)
        {
            if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (string value in header.Value)
            {
                sb.Append(header.Key).Append(": ").Append(value).Append("\r\n");
            }
        }

        if (useCookies && cookieContainer is not null)
        {
            string cookieHeader = cookieContainer.GetCookieHeader(uri);
            if (!string.IsNullOrEmpty(cookieHeader))
            {
                sb.Append("Cookie: ").Append(cookieHeader).Append("\r\n");
            }
        }

        if (body is not null)
        {
            sb.Append("Content-Length: ").Append(body.Length).Append("\r\n");

            foreach (KeyValuePair<string, IEnumerable<string>> header in request.Content!.Headers)
            {
                if (header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (string value in header.Value)
                {
                    sb.Append(header.Key).Append(": ").Append(value).Append("\r\n");
                }
            }
        }

        sb.Append("\r\n");

        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static string BuildRequestTarget(HttpRequestMessage request, Uri uri, bool absoluteForm)
    {
        if (absoluteForm)
        {
            // Plaintext HTTP through a proxy uses absolute-form (no CONNECT).
            return uri.AbsoluteUri;
        }

        return uri.PathAndQuery;
    }

    private static string BuildAcceptEncoding(DecompressionMethods encodings)
    {
        var list = new List<string>();
        if (encodings.HasFlag(DecompressionMethods.GZip))
        {
            list.Add("gzip");
        }

        if (encodings.HasFlag(DecompressionMethods.Deflate))
        {
            list.Add("deflate");
        }

        if (encodings.HasFlag(DecompressionMethods.Brotli))
        {
            list.Add("br");
        }

        return list.Count == 0 ? "identity" : string.Join(", ", list);
    }
}
