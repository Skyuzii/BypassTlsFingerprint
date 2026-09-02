using System.Collections.Concurrent;

namespace BypassTlsFingerprint;

/// <summary>Identifies a group of interchangeable connections.</summary>
internal readonly record struct Endpoint(string Scheme, string Host, int Port)
{
    public override string ToString()
    {
        return $"{Scheme}://{Host}:{Port}";
    }
}

/// <summary>
/// A small connection pool keyed by <see cref="Endpoint"/>. It enables HTTP/1.1 keep-alive by reusing
/// established (incl. TLS) connections across requests, prunes idle/expired connections and caps the
/// number of concurrent connections per endpoint.
/// </summary>
/// <remarks>
/// Mirrors <c>SocketsHttpHandler</c>'s pool shape: idle HTTP/1.1 connections are kept in a lock-free
/// LIFO stack (<c>ConcurrentStack</c>), and expiry is checked both on checkout and on return so an
/// expired connection never waits in the pool for the next caller to discover.
/// </remarks>
internal sealed class HttpConnectionPool
{
    private readonly TimeSpan _idleTimeout;
    private readonly TimeSpan _lifetime;
    private readonly Func<Endpoint, CancellationToken, Task<HttpConnection>> _factory;
    private readonly ConcurrentDictionary<Endpoint, EndpointPool> _pools = new ConcurrentDictionary<Endpoint, EndpointPool>();

    public HttpConnectionPool(TimeSpan idleTimeout, TimeSpan lifetime, Func<Endpoint, CancellationToken, Task<HttpConnection>> factory)
    {
        _idleTimeout = idleTimeout;
        _lifetime = lifetime;
        _factory = factory;
    }

    /// <summary>Rents a connection for <paramref name="key"/>, creating or reusing one as appropriate.</summary>
    public async Task<HttpConnection> RentAsync(Endpoint key, int maxPerServer, CancellationToken ct)
    {
        EndpointPool pool = _pools.GetOrAdd(key, k => new EndpointPool(_factory, _idleTimeout, _lifetime, k));
        return await pool.RentAsync(maxPerServer, ct).ConfigureAwait(false);
    }

    /// <summary>Returns a connection to the pool, or disposes it when it is no longer reusable.</summary>
    public void Return(HttpConnection connection, Endpoint key)
    {
        if (_pools.TryGetValue(key, out EndpointPool? pool))
        {
            pool.Return(connection);
        }
        else
        {
            connection.Dispose();
        }
    }

    public void Dispose()
    {
        foreach (EndpointPool pool in _pools.Values)
        {
            pool.Dispose();
        }

        _pools.Clear();
    }

    private sealed class EndpointPool
    {
        private readonly Func<Endpoint, CancellationToken, Task<HttpConnection>> _factory;
        private readonly TimeSpan _idleTimeout;
        private readonly TimeSpan _lifetime;
        private readonly Endpoint _key;

        // Lock-free LIFO: the most recently used connection is the least likely to have been closed by
        // the peer, which is exactly SocketsHttpHandler's rationale for a stack.
        private readonly ConcurrentStack<HttpConnection> _idle = new ConcurrentStack<HttpConnection>();
        private SemaphoreSlim? _semaphore;

        public EndpointPool(Func<Endpoint, CancellationToken, Task<HttpConnection>> factory, TimeSpan idleTimeout, TimeSpan lifetime, Endpoint key)
        {
            _factory = factory;
            _idleTimeout = idleTimeout;
            _lifetime = lifetime;
            _key = key;
        }

        public async Task<HttpConnection> RentAsync(int maxPerServer, CancellationToken ct)
        {
            SemaphoreSlim semaphore = GetSemaphore(maxPerServer);
            await semaphore.WaitAsync(ct).ConfigureAwait(false);

            try
            {
                // Pop candidates until a live, non-expired one is found.
                while (_idle.TryPop(out HttpConnection? candidate))
                {
                    if (candidate.IsReusable && !candidate.IsExpired(_idleTimeout) && !candidate.IsPastLifetime(_lifetime))
                    {
                        candidate.MarkUsed();
                        return candidate; // the semaphore slot stays owned by the active caller
                    }

                    candidate.Dispose();
                }

                return await _factory(_key, ct).ConfigureAwait(false);
            }
            catch
            {
                semaphore.Release();
                throw;
            }
        }

        public void Return(HttpConnection connection)
        {
            // Check expiry on return too: an expired connection must not sit in the pool until the next
            // caller pops and discards it. Matches SocketsHttpHandler's CheckExpirationOnReturn.
            if (!connection.IsReusable || connection.IsExpired(_idleTimeout) || connection.IsPastLifetime(_lifetime))
            {
                connection.Dispose();
                _semaphore?.Release();
                return;
            }

            connection.MarkUsed();
            _idle.Push(connection);
            // The semaphore slot stays owned while the connection idles in the pool.
        }

        private SemaphoreSlim GetSemaphore(int maxPerServer)
        {
            if (_semaphore is not null)
            {
                return _semaphore;
            }

            var created = new SemaphoreSlim(Math.Max(val1: 1, maxPerServer), Math.Max(val1: 1, maxPerServer));
            return Interlocked.CompareExchange(ref _semaphore, created, comparand: null) ?? created;
        }

        public void Dispose()
        {
            while (_idle.TryPop(out HttpConnection? connection))
            {
                connection.Dispose();
            }
        }
    }
}
