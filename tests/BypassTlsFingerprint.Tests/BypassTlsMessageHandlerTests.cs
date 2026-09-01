using System.Net;
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

        string response = await httpClient.GetStringAsync("https://io.dexscreener.com/u/search/pairs?q=0x6e2ac0524b447c01f4a96e869ccafd66449e6800");

        Assert.That(response, Is.Not.Null.And.Not.Empty);
    }

    [Test]
    public async Task GetStringWithProxy_ShouldUseProxy()
    {
        const int proxyPort = 8000;
        const string proxyHost = "185.126.84.204";

        BypassTlsMessageHandler handler = CreateHandler(h =>
        {
            h.ProxyHost = proxyHost;
            h.ProxyPort = proxyPort;
        });
        using var httpClient = new HttpClient(handler);

        string response = await httpClient.GetStringAsync("https://2ip.ru/");

        string responseProxyHost = Regex.Match(response, "return 'IP адрес: (.*?)'").Groups[1].Value;
        Assert.That(responseProxyHost, Is.EqualTo(proxyHost));
    }
}
