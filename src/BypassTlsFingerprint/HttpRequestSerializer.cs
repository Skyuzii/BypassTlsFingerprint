using System.Buffers;
using System.Globalization;
using System.Net;
using System.Text;

namespace BypassTlsFingerprint;

/// <summary>
/// Serializes the outbound HTTP/1.1 request head (request line + headers) directly into a pooled byte
/// buffer, avoiding the <c>StringBuilder</c>→<c>string</c>→<c>byte[]</c> triple allocation of the old
/// implementation. The body is written separately by the caller so a full request body is never copied
/// into a combined buffer.
/// </summary>
internal static class HttpRequestSerializer
{
    /// <summary>ASCII letters and digits written the most; we emit raw bytes to skip UTF-8 validation.</summary>
    private const byte CR = (byte)'\r';
    private const byte LF = (byte)'\n';
    private const byte SP = (byte)' ';
    private const byte COLON = (byte)':';

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

        var writer = new ArrayBufferWriter<byte>(1024);

        // Request line: "GET /path?query HTTP/1.1\r\n"
        WriteAscii(writer, request.Method.Method);
        writer.GetSpan(1)[0] = SP;
        writer.Advance(1);
        WriteAscii(writer, target);
        WriteAscii(writer, " HTTP/1.1\r\n");

        // Host header.
        WriteAscii(writer, "Host: ");
        WriteAscii(writer, request.Headers.Host ?? uri.Authority);
        WriteCrlf(writer);

        if (automaticDecompression != DecompressionMethods.None)
        {
            WriteAscii(writer, "Accept-Encoding: ");
            WriteAcceptEncoding(writer, automaticDecompression);
            WriteCrlf(writer);
        }

        foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers)
        {
            if (header.Key.Equals("Host", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            WriteHeader(writer, header.Key, header.Value);
        }

        if (useCookies && cookieContainer is not null)
        {
            string cookieHeader = cookieContainer.GetCookieHeader(uri);
            if (!string.IsNullOrEmpty(cookieHeader))
            {
                WriteAscii(writer, "Cookie: ");
                WriteAscii(writer, cookieHeader);
                WriteCrlf(writer);
            }
        }

        if (body is not null)
        {
            WriteAscii(writer, "Content-Length: ");
            WriteAscii(writer, body.Length.ToString(CultureInfo.InvariantCulture));
            WriteCrlf(writer);

            foreach (KeyValuePair<string, IEnumerable<string>> header in request.Content!.Headers)
            {
                if (header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                WriteHeader(writer, header.Key, header.Value);
            }
        }

        WriteCrlf(writer);

        return writer.WrittenSpan.ToArray();
    }

    private static void WriteHeader(ArrayBufferWriter<byte> writer, string name, IEnumerable<string> values)
    {
        // A header with multiple values is emitted as repeated "Name: value\r\n" lines — this is how
        // HttpClient serializes multi-valued headers and what servers expect.
        foreach (string value in values)
        {
            WriteAscii(writer, name);
            writer.GetSpan(1)[0] = COLON;
            writer.Advance(1);
            writer.GetSpan(1)[0] = SP;
            writer.Advance(1);
            WriteAscii(writer, value);
            WriteCrlf(writer);
        }
    }

    private static void WriteAcceptEncoding(ArrayBufferWriter<byte> writer, DecompressionMethods encodings)
    {
        var first = true;
        if ((encodings & DecompressionMethods.GZip) != 0)
        {
            WriteAscii(writer, "gzip");
            first = false;
        }

        if ((encodings & DecompressionMethods.Deflate) != 0)
        {
            if (!first)
            {
                WriteAscii(writer, ", ");
            }

            WriteAscii(writer, "deflate");
            first = false;
        }

        if ((encodings & DecompressionMethods.Brotli) != 0)
        {
            if (!first)
            {
                WriteAscii(writer, ", ");
            }

            WriteAscii(writer, "br");
        }
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

    private static void WriteAscii(ArrayBufferWriter<byte> writer, string value)
    {
        int needed = Encoding.ASCII.GetByteCount(value);
        Span<byte> span = writer.GetSpan(needed);
        int written = Encoding.ASCII.GetBytes(value, span);
        writer.Advance(written);
    }

    private static void WriteCrlf(ArrayBufferWriter<byte> writer)
    {
        Span<byte> span = writer.GetSpan(2);
        span[0] = CR;
        span[1] = LF;
        writer.Advance(2);
    }
}
