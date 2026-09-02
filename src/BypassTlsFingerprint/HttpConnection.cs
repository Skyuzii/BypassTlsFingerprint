using System.Net.Sockets;

namespace BypassTlsFingerprint;

internal sealed class HttpConnection : IDisposable
{
    private readonly TcpClient _client;
    private long _lastUsedTicks;

    public Stream Stream { get; }

    public bool IsTls { get; }

    public string Host { get; }

    public bool IsReusable { get; set; } = true;

    public HttpConnection(TcpClient client, Stream httpStream, bool isTls, string host)
    {
        _client = client;
        Stream = new BufferedStream(httpStream, bufferSize: 8192);
        IsTls = isTls;
        Host = host;
        MarkUsed();
    }

    public void MarkUsed()
    {
        _lastUsedTicks = Environment.TickCount64;
    }

    public bool IsExpired(TimeSpan idleTimeout)
    {
        return idleTimeout > TimeSpan.Zero && Environment.TickCount64 - _lastUsedTicks > (long)idleTimeout.TotalMilliseconds;
    }

    public void Dispose()
    {
        try
        {
            _client.Dispose();
        }
        catch (Exception)
        {
            // ignore
        }

        try
        {
            Stream.Dispose();
        }
        catch (Exception)
        {
            // ignore
        }
    }
}
