using System.Buffers;

namespace BypassTlsFingerprint;

/// <summary>
/// Reads length-prefixed and line-delimited fragments from a stream using a single look-ahead buffer,
/// avoiding byte-by-byte reads. Mirrors the buffered approach of <c>SocketsHttpHandler</c>'s
/// <c>HttpConnection</c>: one fill moves many bytes, CRLF boundaries are located over spans, and bytes
/// read past a boundary (e.g. the start of the body arriving with the head) are kept for the next read.
/// </summary>
internal sealed class HttpLineReader : IDisposable
{
    /// <summary>Largest head (status line + headers) we accept. Defends against malformed peers.</summary>
    private const int MaxHeadBytes = 64 * 1024;

    private const int InitialCapacity = 4096;

    private readonly Stream _stream;
    private byte[] _buffer = ArrayPool<byte>.Shared.Rent(InitialCapacity);
    private int _length;   // valid bytes in _buffer
    private int _offset;   // next unconsumed byte in _buffer

    internal HttpLineReader(Stream stream)
    {
        _stream = stream;
    }

    /// <summary>
    /// Reads the response head up to and including the terminating blank line (<c>\r\n\r\n</c>).
    /// Throws if the head exceeds <see cref="MaxHeadBytes"/> or the stream closes before the terminator.
    /// Bytes read past the terminator are retained and served by subsequent reads.
    /// </summary>
    public async Task<byte[]> ReadHeadAsync(CancellationToken ct)
    {
        var head = new byte[InitialCapacity];
        var headLen = 0;

        while (true)
        {
            if (headLen == head.Length)
            {
                Array.Resize(ref head, head.Length * 2);
            }

            // Consume the look-ahead buffer first, then read from the stream.
            int available = _length - _offset;
            int read;
            if (available > 0)
            {
                int toCopy = Math.Min(available, head.Length - headLen);
                Buffer.BlockCopy(_buffer, _offset, head, headLen, toCopy);
                _offset += toCopy;
                read = toCopy;
            }
            else
            {
                read = await _stream.ReadAsync(head.AsMemory(headLen), ct);
                if (read == 0)
                {
                    throw new EndOfStreamException("Connection closed before the response head terminator.");
                }
            }

            headLen += read;

            int headerEnd = IndexOfCrlfCrlf(head, headLen);
            if (headerEnd >= 0)
            {
                int end = headerEnd + 4;

                // Push bytes read past the head boundary back into the look-ahead buffer so the body
                // reader sees them. One ReadAsync frequently returns the head *and* the start of the
                // body together — this is the key advantage over byte-by-byte readers.
                int leftover = headLen - end;
                if (leftover > 0)
                {
                    PushBack(head, end, leftover);
                }

                Array.Resize(ref head, end);
                return head;
            }

            if (headLen > MaxHeadBytes)
            {
                throw new HttpRequestException($"Response head exceeded the {MaxHeadBytes}-byte limit.");
            }
        }
    }

    /// <summary>
    /// Reads a single line without the trailing CRLF. Returns an empty array for a blank line
    /// (used to detect the end of chunk trailers). Returns <c>null</c> at EOF with nothing read.
    /// </summary>
    public async Task<byte[]?> ReadLineAsync(CancellationToken ct)
    {
        using var acc = new LineAccumulator();

        while (true)
        {
            if (_offset >= _length && !await FillAsync(ct))
            {
                return acc.IsEmpty ? null : acc.ToArray();
            }

            ReadOnlySpan<byte> available = _buffer.AsSpan(_offset, _length - _offset);
            int lf = available.IndexOf((byte)'\n');
            if (lf >= 0)
            {
                int lineEnd = _offset + lf;
                // Strip a preceding CR if present.
                int copyLen = (lf > 0 && _buffer[lineEnd - 1] == (byte)'\r') ? lf - 1 : lf;
                var line = new byte[copyLen];
                if (copyLen > 0)
                {
                    acc.CopyTo(line);
                    Buffer.BlockCopy(_buffer, _offset, line, acc.Length, copyLen - acc.Length);
                }

                _offset = lineEnd + 1;
                return line;
            }

            // No terminator yet: append what we have and refill.
            acc.Append(available);
            _offset = _length;
        }
    }

    /// <summary>
    /// Reads exactly <paramref name="count"/> body bytes. Leftover bytes in the look-ahead buffer are
    /// consumed first, then the stream is read for the remainder.
    /// </summary>
    public async Task<byte[]> ReadBytesAsync(int count, CancellationToken ct)
    {
        var result = new byte[count];
        var filled = 0;

        // Consume look-ahead first.
        int available = _length - _offset;
        if (available > 0)
        {
            int toCopy = Math.Min(available, count);
            Buffer.BlockCopy(_buffer, _offset, result, dstOffset: 0, toCopy);
            _offset += toCopy;
            filled += toCopy;
        }

        while (filled < count)
        {
            int read = await _stream.ReadAsync(result.AsMemory(filled, count - filled), ct);
            if (read == 0)
            {
                throw new EndOfStreamException("Connection closed before the response body was fully read.");
            }

            filled += read;
        }

        return result;
    }

    /// <summary>Reads until EOF (close-delimited body), growing as needed.</summary>
    public async Task<byte[]> ReadUntilEofAsync(CancellationToken ct)
    {
        using var body = new MemoryStream();

        // Consume look-ahead first.
        int available = _length - _offset;
        if (available > 0)
        {
            await body.WriteAsync(_buffer.AsMemory(_offset, available), ct);
            _offset = _length;
        }

        byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            while (true)
            {
                int read = await _stream.ReadAsync(buffer, ct);
                if (read == 0)
                {
                    break;
                }

                await body.WriteAsync(buffer.AsMemory(start: 0, read), ct);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return body.ToArray();
    }

    /// <summary>Skips exactly <paramref name="count"/> bytes (used to consume the CRLF after a chunk).</summary>
    public async Task SkipBytesAsync(int count, CancellationToken ct)
    {
        var skipped = 0;
        while (skipped < count)
        {
            int available = _length - _offset;
            if (available > 0)
            {
                int toSkip = Math.Min(available, count - skipped);
                _offset += toSkip;
                skipped += toSkip;
                continue;
            }

            if (!await FillAsync(ct))
            {
                throw new EndOfStreamException("Connection closed while skipping framing bytes.");
            }
        }
    }

    private async Task<bool> FillAsync(CancellationToken ct)
    {
        int read = await _stream.ReadAsync(_buffer, ct);
        if (read == 0)
        {
            _length = 0;
            _offset = 0;
            return false;
        }

        _length = read;
        _offset = 0;
        return true;
    }

    private void PushBack(byte[] source, int sourceOffset, int count)
    {
        if (count > _buffer.Length)
        {
            ArrayPool<byte>.Shared.Return(_buffer);
            _buffer = ArrayPool<byte>.Shared.Rent(count);
        }

        Buffer.BlockCopy(source, sourceOffset, _buffer, dstOffset: 0, count);
        _length = count;
        _offset = 0;
    }

    private static int IndexOfCrlfCrlf(byte[] buffer, int length)
    {
        int limit = length - 4;
        for (var i = 0; i <= limit; i++)
        {
            if (buffer[i] == (byte)'\r' && buffer[i + 1] == (byte)'\n' &&
                buffer[i + 2] == (byte)'\r' && buffer[i + 3] == (byte)'\n')
            {
                return i;
            }
        }

        return -1;
    }

    public void Dispose()
    {
        ArrayPool<byte>.Shared.Return(_buffer);
    }

    /// <summary>
    /// Accumulates line bytes across multiple fills without knowing the final length up-front,
    /// growing a rented buffer as needed.
    /// </summary>
    private sealed class LineAccumulator : IDisposable
    {
        private byte[] _buffer = ArrayPool<byte>.Shared.Rent(256);
        private int _length;

        public int Length => _length;

        public bool IsEmpty => _length == 0;

        public void Append(ReadOnlySpan<byte> data)
        {
            if (_length + data.Length > _buffer.Length)
            {
                int newSize = _buffer.Length;
                while (newSize < _length + data.Length)
                {
                    newSize *= 2;
                }

                byte[] grown = ArrayPool<byte>.Shared.Rent(newSize);
                Buffer.BlockCopy(_buffer, srcOffset: 0, grown, dstOffset: 0, _length);
                ArrayPool<byte>.Shared.Return(_buffer);
                _buffer = grown;
            }

            data.CopyTo(_buffer.AsSpan(_length));
            _length += data.Length;
        }

        public void CopyTo(byte[] destination)
        {
            Buffer.BlockCopy(_buffer, srcOffset: 0, destination, dstOffset: 0, _length);
        }

        public byte[] ToArray()
        {
            var result = new byte[_length];
            Buffer.BlockCopy(_buffer, srcOffset: 0, result, dstOffset: 0, _length);
            return result;
        }

        public void Dispose()
        {
            ArrayPool<byte>.Shared.Return(_buffer);
        }
    }
}
