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

    /// <summary>
    /// Decompresses the response body when <paramref name="automaticDecompression"/> advertises a matching
    /// encoding. Returns a new <see cref="HttpResponse"/> with decoded content and the on-the-wire framing
    /// headers removed; the original is left untouched.
    /// </summary>
    public static HttpResponse Decompress(HttpResponse parsed, DecompressionMethods automaticDecompression)
    {
        string? contentEncoding = HttpHeaders.GetHeader(parsed.Headers, "Content-Encoding");
        if (string.IsNullOrEmpty(contentEncoding) || parsed.Content.Length == 0)
        {
            return parsed;
        }

        string token = contentEncoding.Split(',')[0].Trim();

        Stream? decompressor = token switch
        {
            "gzip" when (automaticDecompression & DecompressionMethods.GZip) != 0
                => new GZipStream(new MemoryStream(parsed.Content), CompressionMode.Decompress),
            "deflate" when (automaticDecompression & DecompressionMethods.Deflate) != 0
                => new DeflateStream(new MemoryStream(parsed.Content), CompressionMode.Decompress),
            "br" when (automaticDecompression & DecompressionMethods.Brotli) != 0
                => new BrotliStream(new MemoryStream(parsed.Content), CompressionMode.Decompress),
            _ => null,
        };

        if (decompressor is null)
        {
            return parsed;
        }

        byte[] decoded;
        using (decompressor)
        {
            using var output = new MemoryStream();
            decompressor.CopyTo(output);
            decoded = output.ToArray();
        }

        // The body is now decoded: rebuild the header list without the on-the-wire framing meta.
        var headers = new List<KeyValuePair<string, string>>(parsed.Headers.Count);
        foreach (KeyValuePair<string, string> header in parsed.Headers)
        {
            if (header.Key.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase) ||
                header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                header.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            headers.Add(header);
        }

        return new HttpResponse
        {
            HttpVersion = parsed.HttpVersion,
            StatusCode = parsed.StatusCode,
            Headers = headers,
            Content = decoded,
            IsConnectionReusable = parsed.IsConnectionReusable,
        };
    }

    /// <summary>
    /// Stores every <c>Set-Cookie</c> header into the container. Each cookie is set individually per
    /// RFC 6265 — concatenating with commas (the old approach) corrupts cookies whose attributes contain
    /// commas (e.g. <c>Expires=Wed, 09 Jun 2021 ...</c>).
    /// </summary>
    public static void AddCookies(HttpResponse parsed, Uri uri, bool useCookies, CookieContainer? cookieContainer)
    {
        if (!useCookies || cookieContainer is null)
        {
            return;
        }

        foreach (KeyValuePair<string, string> header in parsed.Headers)
        {
            if (header.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    cookieContainer.SetCookies(uri, header.Value);
                }
                catch (CookieException)
                {
                    // A malformed cookie must not abort the response; skip it like HttpClient does.
                }
            }
        }
    }

    private static Version ParseVersion(string httpVersion)
    {
        return httpVersion switch
        {
            "HTTP/1.0" => HttpVersion.Version10,
            _ => HttpVersion.Version11,
        };
    }
}
