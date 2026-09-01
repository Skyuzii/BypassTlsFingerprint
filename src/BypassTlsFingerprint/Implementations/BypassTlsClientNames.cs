namespace BypassTlsFingerprint.Implementations;

/// <summary>
/// Names of the <see cref="Abstractions.BrowserTlsClient"/> implementations available via
/// <see cref="BypassTlsMessageHandlerFactory"/> and the DI registration.
/// </summary>
public static class BypassTlsClientNames
{
    public const string Mozila = nameof(TlsClients.MozilaTlsClient);
}
