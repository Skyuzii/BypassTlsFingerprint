using BypassTlsFingerprint.Implementations;

using Microsoft.Extensions.DependencyInjection;

namespace BypassTlsFingerprint.Registrars;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds an <see cref="HttpClient"/> (via <see cref="IHttpClientFactory"/>) that uses
    /// <see cref="BypassTlsMessageHandler"/> with the given browser TLS fingerprint.
    /// </summary>
    public static IHttpClientBuilder AddBypassHttpClient(
        this IServiceCollection services,
        string clientName = BypassTlsClientNames.Mozila,
        string tlsClientName = BypassTlsClientNames.Mozila,
        Action<BypassTlsMessageHandler>? configureHandler = null)
    {
        return services.AddHttpClient(clientName)
            .ConfigurePrimaryHttpMessageHandler(() =>
            {
                BypassTlsMessageHandler handler = new BypassTlsMessageHandlerFactory().GetMessageHandler(tlsClientName);
                configureHandler?.Invoke(handler);
                return handler;
            });
    }
}