using System.Text.RegularExpressions;

using BypassTlsFingerprint.Extensions;

namespace BypassTlsFingerprint.Tests;

internal sealed class BypassHttpClientTests
{
    private const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36";

    [Test]
    public async Task GetResponse_ShouldReturnResponse()
    {
        var httpClientFactory = new BypassHttpClientFactory();
        var httpClient = httpClientFactory
            .GetHttpClient()
            .WithUserAgent(UserAgent);

        var response = await httpClient.GetResponse("https://auto.ru/cars/used/");
        Assert.That(response.Cookies.Count > 0, Is.True);
        Assert.That(!string.IsNullOrEmpty(response.Content), Is.True);
    }

    [Test]
    public async Task GetResponseString_ShouldReturnResponseString()
    {
        var httpClientFactory = new BypassHttpClientFactory();
        var httpClient = httpClientFactory
            .GetHttpClient()
            .WithUserAgent(UserAgent);

        var response = await httpClient.GetResponseString("https://io.dexscreener.com/u/search/pairs?q=0x6e2ac0524b447c01f4a96e869ccafd66449e6800");
        Assert.That(!string.IsNullOrEmpty(response), Is.True);
    }

    [Test]
    public async Task GetResponseStringWithProxy_ShouldReturnResponseString()
    {
        const int proxyPort = 8000;
        const string proxyHost = "185.126.84.204";
        var httpClientFactory = new BypassHttpClientFactory();
        var httpClient = httpClientFactory
            .GetHttpClient()
            .WithProxy(proxyHost, proxyPort)
            .WithUserAgent(UserAgent);

        var response = await httpClient.GetResponseString("https://2ip.ru/");
        Assert.That(response, Is.Not.EqualTo(null));

        var responseProxyPort = Regex.Match(response, "return 'IP адрес: (.*?)'").Groups[1].Value;
        Assert.That(proxyHost == responseProxyPort, Is.True);
    }

}