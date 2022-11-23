using System.Net;

namespace BypassTlsFingerprint.Extensions;

public static class BypassHttpClientExtensions
{
    public static BypassHttpClient WithHeader(this BypassHttpClient httpClient, string name, string value)
    {
        if (httpClient.Headers.ContainsKey(name))
        {
            httpClient.Headers[name] = value;
        }
        else
        {
            httpClient.Headers.Add(name, value);
        }

        return httpClient;
    }

    public static BypassHttpClient WithHeaders(this BypassHttpClient httpClient, Dictionary<string, string> headers)
    {
        foreach (var header in headers)
        {
            httpClient.Headers.Add(header.Key, header.Value);
        }

        return httpClient;
    }

    public static BypassHttpClient WithMethod(this BypassHttpClient httpClient, HttpMethod method)
    {
        httpClient.Method = method;
        return httpClient;
    }

    public static BypassHttpClient WithCookies(this BypassHttpClient httpClient, CookieCollection cookies)
    {
        httpClient.Cookies = cookies;
        return httpClient;
    }

    public static BypassHttpClient WithProxy(this BypassHttpClient httpClient, string proxy, int port)
    {
        httpClient.ProxyHost = proxy;
        httpClient.ProxyPort = port;
        return httpClient;
    }

    public static BypassHttpClient WithProxy(this BypassHttpClient httpClient, string proxyAndPort)
    {
        var arr = proxyAndPort.Split(':');
        return httpClient.WithProxy(arr[0], int.Parse(arr[1]));
    }

    public static BypassHttpClient WithUserAgent(this BypassHttpClient httpClient, string userAgent)
    {
        httpClient.UserAgent = userAgent;
        return httpClient;
    }
}