using System.Text;

namespace BypassTlsFingerprint.Tests.Support;

/// <summary>Helpers to read HTTP/1.1 requests and write raw responses on a stream.</summary>
public static class FakeHttp
{
    /// <summary>
    /// Reads a single HTTP/1.1 request head + body from <paramref name="stream"/>.
    /// Returns <c>null</c> when the peer closes the connection before a request is received.
    /// </summary>
    public static async Task<FakeRequest?> TryReadRequestAsync(Stream stream, CancellationToken ct = default)
    {
        var head = new List<byte>(512);
        var buffer = new byte[1];
        var foundHeaderEnd = false;

        while (!foundHeaderEnd)
        {
            int n = await stream.ReadAsync(buffer, ct);
            if (n == 0)
            {
                return head.Count == 0 ? null : throw new EndOfStreamException("Connection closed mid-request.");
            }

            head.Add(buffer[0]);
            if (head.Count >= 4 &&
                head[^4] == (byte)'\r' && head[^3] == (byte)'\n' &&
                head[^2] == (byte)'\r' && head[^1] == (byte)'\n')
            {
                foundHeaderEnd = true;
            }
        }

        string headText = Encoding.ASCII.GetString(head.ToArray());
        string[] lines = headText.Replace("\r\n", "\n").Split(separator: '\n', StringSplitOptions.RemoveEmptyEntries);

        string[] requestLine = lines[0].Split(' ');
        var request = new FakeRequest
        {
            Method = requestLine[0],
            Path = requestLine.Length > 1 ? requestLine[1] : "/",
        };
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 1; i < lines.Length; i++)
        {
            int colon = lines[i].IndexOf(':');
            if (colon > 0)
            {
                headers[lines[i][..colon].Trim()] = lines[i][(colon + 1)..].Trim();
            }
        }

        byte[] body = Array.Empty<byte>();
        if (headers.TryGetValue("Content-Length", out string? lengthText) &&
            int.TryParse(lengthText, out int length) &&
            length > 0)
        {
            body = new byte[length];
            var totalRead = 0;
            while (totalRead < length)
            {
                int read = await stream.ReadAsync(body.AsMemory(totalRead), ct);
                if (read == 0)
                {
                    throw new EndOfStreamException("Connection closed mid-body.");
                }

                totalRead += read;
            }
        }

        return new FakeRequest
        {
            Method = request.Method,
            Path = request.Path,
            Headers = headers,
            Body = body,
        };
    }

    /// <summary>Writes a single buffered response. HTTP/1.1 requires CRLF — never Environment.NewLine.</summary>
    public static async Task WriteResponseAsync(Stream stream, FakeResponse response, CancellationToken ct = default)
    {
        var sb = new StringBuilder();
        sb.Append(response.StatusLine).Append("\r\n");

        var hasContentLength = false;
        foreach (KeyValuePair<string, string> header in response.Headers)
        {
            sb.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
            if (header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
            {
                hasContentLength = true;
            }
        }

        if (!hasContentLength)
        {
            sb.Append("Content-Length: ").Append(response.Body.Length).Append("\r\n");
        }

        if (response.CloseConnection)
        {
            sb.Append("Connection: close\r\n");
        }

        sb.Append("\r\n");

        byte[] head = Encoding.ASCII.GetBytes(sb.ToString());
        var data = new byte[head.Length + response.Body.Length];
        Buffer.BlockCopy(head, srcOffset: 0, data, dstOffset: 0, head.Length);
        Buffer.BlockCopy(response.Body, srcOffset: 0, data, head.Length, response.Body.Length);
        await stream.WriteAsync(data, ct);
        await stream.FlushAsync(ct);
    }

    /// <summary>Writes a response whose body is encoded with chunked transfer-encoding.</summary>
    public static async Task WriteChunkedResponseAsync(
        Stream stream,
        string statusLine,
        IEnumerable<KeyValuePair<string, string>> headers,
        byte[] body,
        int chunkSize,
        CancellationToken ct = default)
    {
        var sb = new StringBuilder();
        sb.Append(statusLine).Append("\r\n");
        foreach (KeyValuePair<string, string> header in headers)
        {
            sb.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
        }

        sb.Append("Transfer-Encoding: chunked\r\n\r\n");

        byte[] head = Encoding.ASCII.GetBytes(sb.ToString());
        await stream.WriteAsync(head, ct);

        var chunkHead = new StringBuilder();
        for (var offset = 0; offset < body.Length; offset += chunkSize)
        {
            int size = Math.Min(chunkSize, body.Length - offset);
            chunkHead.Append(size.ToString("x"));
            chunkHead.Append("\r\n");
            await stream.WriteAsync(Encoding.ASCII.GetBytes(chunkHead.ToString()), ct);
            await stream.WriteAsync(body.AsMemory(offset, size), ct);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("\r\n"), ct);
            chunkHead.Clear();
        }

        await stream.WriteAsync(Encoding.ASCII.GetBytes("0\r\n\r\n"), ct);
        await stream.FlushAsync(ct);
    }

    /// <summary>Writes raw bytes verbatim.</summary>
    public static async Task WriteRawAsync(Stream stream, string raw, CancellationToken ct = default)
    {
        byte[] data = Encoding.ASCII.GetBytes(raw);
        await stream.WriteAsync(data, ct);
        await stream.FlushAsync(ct);
    }
}
