namespace BypassTlsFingerprint;

/// <summary>
/// A read-only stream that yields a prefix of already-buffered bytes before falling through to an inner
/// stream. Used to re-parse a response head that was read eagerly (e.g. during Expect: 100-continue) without
/// losing those bytes.
/// </summary>
internal sealed class PrependStream : Stream
{
    private readonly Stream _inner;
    private byte[] _prefix;
    private int _offset;

    public PrependStream(Stream inner, byte[] prefix)
    {
        _inner = inner;
        _prefix = prefix;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_offset < _prefix.Length)
        {
            int fromPrefix = Math.Min(count, _prefix.Length - _offset);
            Buffer.BlockCopy(_prefix, _offset, buffer, offset, fromPrefix);
            _offset += fromPrefix;
            return fromPrefix;
        }

        return _inner.Read(buffer, offset, count);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_offset < _prefix.Length)
        {
            int fromPrefix = Math.Min(buffer.Length, _prefix.Length - _offset);
            _prefix.AsMemory(_offset, fromPrefix).CopyTo(buffer);
            _offset += fromPrefix;
            return fromPrefix;
        }

        return await _inner.ReadAsync(buffer, ct);
    }

    public override int ReadByte()
    {
        if (_offset < _prefix.Length)
        {
            return _prefix[_offset++];
        }

        return _inner.ReadByte();
    }

    public override void Flush()
    {
        _inner.Flush();
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _prefix = Array.Empty<byte>();
        }

        base.Dispose(disposing);
    }
}
