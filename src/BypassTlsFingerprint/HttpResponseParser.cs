using System.Globalization;
using System.Text;

namespace BypassTlsFingerprint;

/// <summary>
/// Parses a single raw HTTP/1.1 response from a stream: the head (status line + headers) via
/// <see cref="HttpLineReader"/>, then the body framed by <c>Content-Length</c>,
/// <c>Transfer-Encoding: chunked</c> (decoded), or close-delimited EOF. The body is buffered as raw
/// bytes (binary preserved); headers keep wire order and may repeat (<c>Set-Cookie</c>).
/// </summary>
internal sealed class HttpResponseParser
{
    public async Task<HttpResponse> Parse(Stream stream, CancellationToken cancellationToken)
    {
        // The reader is created per parse so its look-ahead buffer never leaks bytes from one response
        // into the next on a pooled connection.
        using var reader = new HttpLineReader(stream);
        byte[] head = await reader.ReadHeadAsync(cancellationToken);
        (string httpVersion, int statusCode, List<KeyValuePair<string, string>> headers) = ParseHead(head);

        byte[] content = await ReadBodyAsync(reader, headers, cancellationToken);

        return new HttpResponse
        {
            HttpVersion = httpVersion,
            StatusCode = statusCode,
            Headers = headers,
            Content = content,
            IsConnectionReusable = ComputeReusability(headers),
        };
    }

    private static (string HttpVersion, int StatusCode, List<KeyValuePair<string, string>> Headers) ParseHead(byte[] head)
    {
        // Split the head into lines over the byte buffer without materializing one big string + Split.
        var headers = new List<KeyValuePair<string, string>>();
        ReadOnlySpan<byte> span = head;

        // The head ends with \r\n\r\n; strip the final blank line so the line walker stops cleanly.
        int headEnd = span.Length - 4;
        span = span[..headEnd];

        // First line: status line.
        int firstLf = span.IndexOf((byte)'\n');
        ReadOnlySpan<byte> statusLine = firstLf < 0 ? span : span[..firstLf];
        statusLine = statusLine.TrimEnd((byte)'\r');

        (string httpVersion, int statusCode) = ParseStatusLine(statusLine);

        if (firstLf >= 0)
        {
            span = span[(firstLf + 1)..];

            while (!span.IsEmpty)
            {
                int lf = span.IndexOf((byte)'\n');
                ReadOnlySpan<byte> line = lf < 0 ? span : span[..lf];
                line = line.TrimEnd((byte)'\r');

                if (!line.IsEmpty)
                {
                    headers.Add(ParseHeaderLine(line));
                }

                if (lf < 0)
                {
                    break;
                }

                span = span[(lf + 1)..];
            }
        }

        return (httpVersion, statusCode, headers);
    }

    private static (string HttpVersion, int StatusCode) ParseStatusLine(ReadOnlySpan<byte> line)
    {
        // "HTTP/1.1 200 OK" — version, status code, optional reason phrase.
        int firstSpace = line.IndexOf((byte)' ');
        if (firstSpace <= 0)
        {
            throw new HttpRequestException($"Invalid HTTP status line - '{Encoding.ASCII.GetString(line)}'");
        }

        ReadOnlySpan<byte> version = line[..firstSpace];
        ReadOnlySpan<byte> rest = line[(firstSpace + 1)..];

        int secondSpace = rest.IndexOf((byte)' ');
        ReadOnlySpan<byte> codeBytes = secondSpace < 0 ? rest : rest[..secondSpace];

        if (!int.TryParse(codeBytes, CultureInfo.InvariantCulture, out int statusCode))
        {
            throw new HttpRequestException($"Invalid HTTP status code - '{Encoding.ASCII.GetString(codeBytes)}'");
        }

        return (Encoding.ASCII.GetString(version), statusCode);
    }

    private static KeyValuePair<string, string> ParseHeaderLine(ReadOnlySpan<byte> line)
    {
        int colon = line.IndexOf((byte)':');
        if (colon <= 0)
        {
            throw new HttpRequestException($"Response contains an invalid header - '{Encoding.ASCII.GetString(line)}'");
        }

        ReadOnlySpan<byte> name = line[..colon];
        ReadOnlySpan<byte> value = line[(colon + 1)..].Trim((byte)' ');
        return new KeyValuePair<string, string>(Encoding.ASCII.GetString(name), Encoding.ASCII.GetString(value));
    }

    private static async Task<byte[]> ReadBodyAsync(HttpLineReader reader, List<KeyValuePair<string, string>> headers, CancellationToken ct)
    {
        string? transferEncoding = HttpHeaders.GetHeader(headers, "Transfer-Encoding");

        if (transferEncoding?.Contains("chunked", StringComparison.OrdinalIgnoreCase) == true)
        {
            return await ReadChunkedBodyAsync(reader, ct);
        }

        string? contentLength = HttpHeaders.GetHeader(headers, "Content-Length");
        if (contentLength is not null && long.TryParse(contentLength, CultureInfo.InvariantCulture, out long length) && length >= 0)
        {
            return length == 0 ? Array.Empty<byte>() : await reader.ReadBytesAsync((int)length, ct);
        }

        // No length and no chunked: close-delimited body.
        return await reader.ReadUntilEofAsync(ct);
    }

    private static async Task<byte[]> ReadChunkedBodyAsync(HttpLineReader reader, CancellationToken ct)
    {
        using var body = new MemoryStream();

        while (true)
        {
            byte[]? sizeLine = await reader.ReadLineAsync(ct);
            if (sizeLine is null)
            {
                throw new EndOfStreamException("Connection closed mid-chunked body.");
            }

            // Chunk extensions (";ext") are discarded — only the hex size matters.
            int semi = sizeLine.AsSpan().IndexOf((byte)';');
            ReadOnlySpan<byte> sizeSpan = semi < 0 ? sizeLine : sizeLine[..semi];

            if (!long.TryParse(sizeSpan, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long size))
            {
                throw new HttpRequestException($"Invalid chunk size - '{Encoding.ASCII.GetString(sizeSpan)}'");
            }

            if (size == 0)
            {
                // Consume any trailer headers up to the terminating blank line ("0\r\n" + trailers + "\r\n").
                while (true)
                {
                    byte[]? trailer = await reader.ReadLineAsync(ct);
                    if (trailer is null || trailer.Length == 0)
                    {
                        break;
                    }
                }

                break;
            }

            byte[] chunk = await reader.ReadBytesAsync((int)size, ct);
            await body.WriteAsync(chunk, ct);

            // Each chunk is followed by CRLF.
            await reader.SkipBytesAsync(count: 2, ct);
        }

        return body.ToArray();
    }

    /// <summary>
    /// A connection is reusable only when the response framing is known (Content-Length or chunked) and
    /// the server did not signal <c>Connection: close</c>. Mirrors SocketsHttpHandler's keep-alive logic.
    /// </summary>
    private static bool ComputeReusability(List<KeyValuePair<string, string>> headers)
    {
        bool knownFraming =
            HttpHeaders.GetHeader(headers, "Content-Length") is not null ||
            HttpHeaders.GetHeader(headers, "Transfer-Encoding") is not null;

        if (!knownFraming)
        {
            return false;
        }

        string? connection = HttpHeaders.GetHeader(headers, "Connection");
        if (connection?.Contains("close", StringComparison.OrdinalIgnoreCase) == true)
        {
            return false;
        }

        return true;
    }
}
