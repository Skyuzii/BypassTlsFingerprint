using System.Text;

namespace BypassTlsFingerprint.Implementations;

/// <summary>
/// Parses a single raw HTTP/1.1 response from a stream. Handles status line, headers and a body
/// framed by <c>Content-Length</c>, <c>Transfer-Encoding: chunked</c> or close-delimited EOF.
/// The body is kept as raw bytes so binary content is preserved.
/// </summary>
public sealed class HttpResponseParser
{
    /// <summary>
    /// Reads one response from <paramref name="stream"/>, returning a buffered result. The stream is left
    /// open and unconsumed-intact so a keep-alive connection can be reused for a subsequent request.
    /// </summary>
    public async Task<HttpResponse> Parse(Stream stream, CancellationToken cancellationToken)
    {
        byte[] head = await ReadHeadAsync(stream, cancellationToken);
        (string httpVersion, int statusCode, List<KeyValuePair<string, string>> headers) = ParseHead(head);

        var response = new HttpResponse
        {
            HttpVersion = httpVersion,
            StatusCode = statusCode,
        };
        response.Headers.AddRange(headers);

        response.Content = await ReadBodyAsync(stream, headers, cancellationToken);
        return response;
    }

    private static async Task<byte[]> ReadHeadAsync(Stream stream, CancellationToken ct)
    {
        var head = new List<byte>(1024);
        var one = new byte[1];

        while (true)
        {
            int n = await stream.ReadAsync(one, ct);
            if (n == 0)
            {
                break; // connection closed; parse whatever head was received
            }

            head.Add(one[0]);
            if (head.Count >= 4 &&
                head[^4] == (byte)'\r' && head[^3] == (byte)'\n' &&
                head[^2] == (byte)'\r' && head[^1] == (byte)'\n')
            {
                break;
            }
        }

        if (head.Count == 0)
        {
            throw new EndOfStreamException("Connection closed before the response head.");
        }

        return head.ToArray();
    }

    private static (string, int, List<KeyValuePair<string, string>>) ParseHead(byte[] head)
    {
        string headText = Encoding.ASCII.GetString(head);
        string[] lines = headText.TrimEnd('\r', '\n').Split('\n');
        string[] statusParts = lines[0].TrimEnd('\r').Split(' ');

        if (statusParts.Length < 2)
        {
            throw new HttpRequestException($"Invalid HTTP status line - '{lines[0]}'");
        }

        string httpVersion = statusParts[0];
        if (!int.TryParse(statusParts[1], out int statusCode))
        {
            throw new HttpRequestException($"Invalid HTTP status code - '{statusParts[1]}'");
        }

        var headers = new List<KeyValuePair<string, string>>();
        for (var i = 1; i < lines.Length; i++)
        {
            string line = lines[i].TrimEnd('\r');
            if (line.Length == 0)
            {
                continue;
            }

            int colon = line.IndexOf(':');
            if (colon < 1)
            {
                throw new HttpRequestException($"Response contains an invalid header - {line}");
            }

            headers.Add(new KeyValuePair<string, string>(line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }

        return (httpVersion, statusCode, headers);
    }

    private static async Task<byte[]> ReadBodyAsync(
        Stream stream,
        List<KeyValuePair<string, string>> headers,
        CancellationToken ct)
    {
        string? transferEncoding = GetHeader(headers, "Transfer-Encoding");

        if (transferEncoding?.Contains("chunked", StringComparison.OrdinalIgnoreCase) == true)
        {
            return await ReadChunkedBodyAsync(stream, ct);
        }

        string? contentLength = GetHeader(headers, "Content-Length");
        if (contentLength is not null && int.TryParse(contentLength, out int length) && length >= 0)
        {
            return length == 0 ? Array.Empty<byte>() : await ReadExactlyAsync(stream, length, ct);
        }

        // No length and no chunked: close-delimited body.
        return await ReadToEndAsync(stream, ct);
    }

    private static async Task<byte[]> ReadChunkedBodyAsync(Stream stream, CancellationToken ct)
    {
        using var body = new MemoryStream();

        while (true)
        {
            string sizeLine = await ReadLineAsync(stream, ct);
            sizeLine = sizeLine.Contains(';') ? sizeLine[..sizeLine.IndexOf(';')] : sizeLine;
            if (!int.TryParse(sizeLine.Trim(), System.Globalization.NumberStyles.HexNumber, provider: null, out int size))
            {
                throw new HttpRequestException($"Invalid chunk size - '{sizeLine}'");
            }

            if (size == 0)
            {
                // Consume any trailer headers up to the terminating blank line ("0\r\n" + trailers + "\r\n").
                while (true)
                {
                    string trailer = await ReadLineAsync(stream, ct);
                    if (trailer.Length == 0)
                    {
                        break;
                    }
                }

                break;
            }

            byte[] chunk = await ReadExactlyAsync(stream, size, ct);
            await body.WriteAsync(chunk, ct);

            // Consume the CRLF that terminates each chunk.
            _ = await ReadExactlyAsync(stream, count: 2, ct);
        }

        return body.ToArray();
    }

    private static Task<string> ReadLineAsync(Stream stream, CancellationToken ct)
    {
        return ReadLineCoreAsync(stream, ct);
    }

    private static async Task<string> ReadLineCoreAsync(Stream stream, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var one = new byte[1];

        while (true)
        {
            int n = await stream.ReadAsync(one, ct);
            if (n == 0)
            {
                break;
            }

            if (one[0] == (byte)'\n')
            {
                break;
            }

            if (one[0] != (byte)'\r')
            {
                sb.Append((char)one[0]);
            }
        }

        return sb.ToString();
    }

    private static async Task<byte[]> ReadExactlyAsync(Stream stream, int count, CancellationToken ct)
    {
        var buffer = new byte[count];
        var total = 0;
        while (total < count)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(total), ct);
            if (read == 0)
            {
                throw new EndOfStreamException("Connection closed before the response body was fully read.");
            }

            total += read;
        }

        return buffer;
    }

    private static async Task<byte[]> ReadToEndAsync(Stream stream, CancellationToken ct)
    {
        using var body = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            int read = await stream.ReadAsync(buffer, ct);
            if (read == 0)
            {
                break;
            }

            await body.WriteAsync(buffer.AsMemory(start: 0, read), ct);
        }

        return body.ToArray();
    }

    private static string? GetHeader(List<KeyValuePair<string, string>> headers, string name)
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
