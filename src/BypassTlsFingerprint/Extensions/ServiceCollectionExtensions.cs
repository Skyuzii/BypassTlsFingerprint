using Microsoft.Extensions.DependencyInjection;

namespace BypassTlsFingerprint.Extensions;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers an <see cref="HttpClient"/> (via <see cref="IHttpClientFactory"/>) that uses
    /// <see cref="BypassTlsMessageHandler"/> with the given browser TLS fingerprint. The default
    /// fingerprint is the library's shipped Firefox profile. Pass a custom
    /// <see cref="TlsFingerprint"/> (built with <see cref="TlsFingerprintBuilder"/>) to impersonate
    /// a different browser/version.
    /// </summary>
    public static IHttpClientBuilder AddBypassHttpClient(
        this IServiceCollection services,
        TlsFingerprint? fingerprint = null,
        Action<BypassTlsMessageHandler>? configureHandler = null,
        string? clientName = null)
    {
        return services.AddHttpClient(clientName ?? "bypass")
            .ConfigurePrimaryHttpMessageHandler(() =>
            {
                var handler = new BypassTlsMessageHandler(fingerprint);
                configureHandler?.Invoke(handler);
                return handler;
            });
    }
}
