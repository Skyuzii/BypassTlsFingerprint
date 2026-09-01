using System.Collections.Concurrent;

namespace BypassTlsFingerprint.Implementations;

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
/// established (incl. TLS) connections across requests, prunes idle connections and caps the number of
/// concurrent connections per endpoint.
/// </summary>
internal sealed class BypassConnectionPool
{
    private readonly TimeSpan _idleTimeout;
    private readonly Func<Endpoint, CancellationToken, Task<BypassConnection>> _factory;
    private readonly ConcurrentDictionary<Endpoint, EndpointPool> _pools = new ConcurrentDictionary<Endpoint, EndpointPool>();

    public BypassConnectionPool(TimeSpan idleTimeout, Func<Endpoint, CancellationToken, Task<BypassConnection>> factory)
    {
        _idleTimeout = idleTimeout;
        _factory = factory;
    }

    /// <summary>Rents a connection for <paramref name="key"/>, creating or reusing one as appropriate.</summary>
    public async Task<BypassConnection> RentAsync(Endpoint key, int maxPerServer, CancellationToken ct)
    {
        EndpointPool pool = _pools.GetOrAdd(key, k => new EndpointPool(_factory, _idleTimeout, k));
        return await pool.RentAsync(maxPerServer, ct).ConfigureAwait(false);
    }

    /// <summary>Returns a connection to the pool, or disposes it when it is no longer reusable.</summary>
    public void Return(BypassConnection connection, Endpoint key)
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
        private readonly Func<Endpoint, CancellationToken, Task<BypassConnection>> _factory;
        private readonly TimeSpan _idleTimeout;
        private readonly Endpoint _key;
        private readonly object _sync = new object();
        private readonly Stack<BypassConnection> _idle = new Stack<BypassConnection>();
        private SemaphoreSlim? _semaphore;

        public EndpointPool(Func<Endpoint, CancellationToken, Task<BypassConnection>> factory, TimeSpan idleTimeout, Endpoint key)
        {
            _factory = factory;
            _idleTimeout = idleTimeout;
            _key = key;
        }

        public async Task<BypassConnection> RentAsync(int maxPerServer, CancellationToken ct)
        {
            SemaphoreSlim semaphore = GetSemaphore(maxPerServer);
            await semaphore.WaitAsync(ct).ConfigureAwait(false);

            try
            {
                lock (_sync)
                {
                    while (_idle.Count > 0)
                    {
                        BypassConnection candidate = _idle.Pop();
                        if (candidate.IsReusable && !candidate.IsExpired(_idleTimeout))
                        {
                            candidate.MarkUsed();
                            return candidate; // the semaphore slot stays owned by the active caller
                        }

                        candidate.Dispose();
                    }
                }

                return await _factory(_key, ct).ConfigureAwait(false);
            }
            catch
            {
                semaphore.Release();
                throw;
            }
        }

        public void Return(BypassConnection connection)
        {
            lock (_sync)
            {
                if (connection.IsReusable)
                {
                    connection.MarkUsed();
                    _idle.Push(connection);
                    return; // keep the slot owned while the connection idles in the pool
                }
            }

            connection.Dispose();
            _semaphore?.Release();
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
            lock (_sync)
            {
                foreach (BypassConnection connection in _idle)
                {
                    connection.Dispose();
                }

                _idle.Clear();
            }
        }
    }
}
