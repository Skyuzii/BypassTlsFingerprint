# BypassTlsFingerprint

A .NET library that impersonates a real browser's TLS/SSL fingerprint (JA3/JA4) and sends raw HTTP/1.1
requests over it, using **BouncyCastle** for TLS instead of .NET's `SocketsHttpHandler`/`SslStream`.

Standard .NET TLS cannot control the ClientHello, so it cannot reproduce a browser's JA3/JA4 fingerprint.
This library can, which is what many anti-bot services check.

## Features

- **Data-driven fingerprints** — a fingerprint is `TlsFingerprint` data, not a class per browser. Covers
  both JA3 and JA4 (extension order and payloads preserved).
- **Custom fingerprints** — build via `TlsFingerprintBuilder`, no BouncyCastle knowledge needed.
- **Standard `HttpClient` handler** — GET/POST/PUT/PATCH/DELETE, redirects, cookies, decompression,
  proxies, connection pooling.
- **DI** — register a named `HttpClient` via `IHttpClientFactory`.
- **.NET 10**, NuGet `BouncyCastle.Cryptography` / `Microsoft.Extensions.Http`.

## Quick start

```csharp
using BypassTlsFingerprint;

// 1. Shipped Firefox profile
var handler = new BypassTlsMessageHandler(TlsFingerprintProfiles.Mozilla.Firefox0);
using var client = new HttpClient(handler);
string body = await client.GetStringAsync("https://example.com/");
```

```csharp
// 2. Custom fingerprint
using BypassTlsFingerprint;
using Org.BouncyCastle.Tls;

var fp = new TlsFingerprintBuilder()
    .WithVersions(TlsVersions.Tls12, TlsVersions.Tls13)
    .WithCipherSuites(4865, 4866, 49195, 49199)
    .AddExtension(ExtensionType.supported_groups, new byte[] { ... })
    .AddExtension(ExtensionType.signature_algorithms, new byte[] { ... })
    .Build();

var handler = new BypassTlsMessageHandler(fp);
```

Extension order = `AddExtension` call order (keep it faithful to the target build). If no `server_name`
extension is added, the builder adds one first.

```csharp
// 3. DI
using BypassTlsFingerprint.Extensions;

services.AddBypassHttpClient(
    TlsFingerprintProfiles.Mozilla.Firefox0,
    handler => handler.MaxConnectionsPerServer = 8);
```

## Configuration

`BypassTlsMessageHandler` mirrors `HttpClientHandler`/`SocketsHttpHandler` options: `Port`,
`AllowAutoRedirect`/`MaxAutomaticRedirections`, `UseCookies`/`CookieContainer`, `UseProxy`/`Proxy`
(`IWebProxy`, defaults to `HttpClient.DefaultProxy`)/`DefaultProxyCredentials`,
`AutomaticDecompression`, `MaxConnectionsPerServer`, `PooledConnectionIdleTimeout`, `ConnectTimeout`.

## Security

Server certificates are **not validated** by default (impersonation's point). Supply your own TLS
authentication if you need verification.
