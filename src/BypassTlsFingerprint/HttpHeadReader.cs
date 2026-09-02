namespace BypassTlsFingerprint;

/// <summary>Reads a raw HTTP response head byte-by-byte, stopping at the terminating CRLFCRLF.</summary>
internal static class HttpHeadReader
{
    public static async Task<byte[]> ReadHeadAsync(Stream stream, CancellationToken ct)
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
}
