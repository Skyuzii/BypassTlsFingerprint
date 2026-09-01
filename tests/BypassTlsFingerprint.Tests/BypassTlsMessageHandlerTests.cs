using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;

using BypassTlsFingerprint.Implementations;

namespace BypassTlsFingerprint.Tests;

internal sealed class BypassTlsMessageHandlerTests
{
    private const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36";

    private static BypassTlsMessageHandler CreateHandler(Action<BypassTlsMessageHandler>? configure = null)
    {
        BypassTlsMessageHandler handler = new BypassTlsMessageHandlerFactory().GetMessageHandler();
        configure?.Invoke(handler);
        return handler;
    }

    [Test]
    public async Task Get_ShouldReturnResponse()
    {
        BypassTlsMessageHandler handler = CreateHandler(h => h.CookieContainer = new CookieContainer());
        using var httpClient = new HttpClient(handler);
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);

        using HttpResponseMessage response = await httpClient.GetAsync("https://auto.ru/cars/used/");

        Assert.That((int)response.StatusCode > 0, Is.True);
        Assert.That(await response.Content.ReadAsStringAsync(), Is.Not.Null);
    }

    [Test]
    public async Task GetString_ShouldReturnContent()
    {
        using var httpClient = new HttpClient(CreateHandler());
        httpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", UserAgent);

        string response = await httpClient.GetStringAsync("https://tls.browserleaks.com/tls");

        Assert.That(response, Is.Not.Null.And.Not.Empty);
    }
}
