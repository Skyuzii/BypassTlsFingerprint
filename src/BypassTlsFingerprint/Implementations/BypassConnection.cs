using System.Net.Sockets;

namespace BypassTlsFingerprint.Implementations;

/// <summary>An established TCP (optionally TLS) connection that can be pooled and reused for keep-alive.</summary>
internal sealed class BypassConnection : IDisposable
{
    private readonly TcpClient _client;
    private long _lastUsedTicks;

    public BypassConnection(TcpClient client, Stream httpStream, bool isTls, string host)
    {
        _client = client;
        // One buffered stream per connection, reused across requests, so header parsing is fast and no
        // extra BufferedStream layers accumulate over the pooled socket.
        Stream = new BufferedStream(httpStream, bufferSize: 8192);
        IsTls = isTls;
        Host = host;
        MarkUsed();
    }

    /// <summary>The HTTP-level stream (raw for http://, the TLS stream for https://), buffered.</summary>
    public Stream Stream { get; }

    public bool IsTls { get; }

    public string Host { get; }

    /// <summary>
    /// Whether this connection can be returned to the pool for a further request. Set to false when the
    /// response was close-delimited or the server/connection indicated it must not be reused.
    /// </summary>
    public bool IsReusable { get; set; } = true;

    public void MarkUsed()
    {
        _lastUsedTicks = Environment.TickCount64;
    }

    public bool IsExpired(TimeSpan idleTimeout)
    {
        return idleTimeout > TimeSpan.Zero &&
               Environment.TickCount64 - _lastUsedTicks > (long)idleTimeout.TotalMilliseconds;
    }

    public void Dispose()
    {
        try
        {
            _client.Dispose();
        }
        catch (Exception)
        {
            // best effort
        }

        try
        {
            Stream.Dispose();
        }
        catch (Exception)
        {
            // best effort
        }
    }
}
