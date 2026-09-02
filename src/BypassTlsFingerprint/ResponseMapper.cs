using System.IO.Compression;
using System.Net;

namespace BypassTlsFingerprint;

/// <summary>Maps a parsed raw response into an <see cref="HttpResponseMessage"/>, handling cookies and decompression.</summary>
internal static class ResponseMapper
{
    public static HttpResponseMessage Build(HttpRequestMessage request, HttpResponse parsed)
    {
        var response = new HttpResponseMessage
        {
            StatusCode = (HttpStatusCode)parsed.StatusCode,
            Version = ParseVersion(parsed.HttpVersion),
            RequestMessage = request,
        };

        var content = new ByteArrayContent(parsed.Content);
        response.Content = content;

        foreach (KeyValuePair<string, string> header in parsed.Headers)
        {
            if (header.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
            {
                // We always deliver a fully buffered body with a Content-Length; drop framing meta.
                continue;
            }

            if (HttpHeaders.IsContentHeader(header.Key))
            {
                content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
            else
            {
                response.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        return response;
    }

    public static HttpResponse Decompress(HttpResponse parsed, DecompressionMethods automaticDecompression)
    {
        string? contentEncoding = HttpHeaders.GetHeader(parsed.Headers, "Content-Encoding");
        if (string.IsNullOrEmpty(contentEncoding) || parsed.Content.Length == 0)
        {
            return parsed;
        }

        Stream? decompressor = null;
        string token = contentEncoding.Split(',')[0].Trim();

        if ((automaticDecompression & DecompressionMethods.GZip) != 0 && token.Equals("gzip", StringComparison.OrdinalIgnoreCase))
        {
            decompressor = new GZipStream(new MemoryStream(parsed.Content), CompressionMode.Decompress);
        }
        else if ((automaticDecompression & DecompressionMethods.Deflate) != 0 && token.Equals("deflate", StringComparison.OrdinalIgnoreCase))
        {
            decompressor = new DeflateStream(new MemoryStream(parsed.Content), CompressionMode.Decompress);
        }
        else if ((automaticDecompression & DecompressionMethods.Brotli) != 0 && token.Equals("br", StringComparison.OrdinalIgnoreCase))
        {
            decompressor = new BrotliStream(new MemoryStream(parsed.Content), CompressionMode.Decompress);
        }

        if (decompressor is null)
        {
            return parsed;
        }

        using (decompressor)
        {
            using var output = new MemoryStream();
            decompressor.CopyTo(output);
            parsed.Content = output.ToArray();
        }

        // The body is now decoded: drop the headers that described the on-the-wire bytes.
        parsed.Headers.RemoveAll(h =>
            h.Key.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase) ||
            h.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
            h.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase));

        return parsed;
    }

    public static void AddCookies(HttpResponse parsed, Uri uri, bool useCookies, CookieContainer? cookieContainer)
    {
        if (!useCookies || cookieContainer is null)
        {
            return;
        }

        string[] setCookies = parsed.Headers
            .Where(h => h.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            .Select(h => h.Value)
            .ToArray();

        if (setCookies.Length == 0)
        {
            return;
        }

        cookieContainer.SetCookies(uri, string.Join(", ", setCookies));
    }

    private static Version ParseVersion(string httpVersion)
    {
        return httpVersion switch
        {
            "HTTP/1.0" => HttpVersion.Version10,
            _ => HttpVersion.Version11
        };
    }
}
