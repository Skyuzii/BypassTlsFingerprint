using System.Net;
using System.Net.Sockets;
using System.Text;

using BypassTlsFingerprint.Abstracts;
using BypassTlsFingerprint.Constants;
using BypassTlsFingerprint.Extensions;
using BypassTlsFingerprint.Models;
using BypassTlsFingerprint.Parsers;

using Org.BouncyCastle.Tls;

namespace BypassTlsFingerprint;

public sealed class BypassHttpClient
{
    private readonly BrowserTlsClient _tlsClient;
    private readonly HttpParser _httpParser = new();

    public bool DisableRedirect { get; set; }
    public HttpMethod Method { get; set; } = HttpMethod.Get;

    public CookieCollection Cookies { get; set; } = new();

    public string? ProxyHost { get; set; }

    public int? ProxyPort { get; set; }

    public string UserAgent { get; set; }

    public Dictionary<string, string> Headers { get; set; } = new();


    public BypassHttpClient(BrowserTlsClient tlsClient)
    {
        _tlsClient = tlsClient;
    }

    public async Task<HttpResponse> GetResponse(string url)
    {
        var response = await GetResponseInternal(url);
        var httpResponse = await _httpParser.ParseHttpResponse(response);

        foreach (Cookie cookie in httpResponse.Cookies)
        {
            Cookies.Add(cookie);
        }

        if (DisableRedirect || !httpResponse.Headers.TryGetValue("Location", out var location))
        {
            return httpResponse;
        }

        return await GetResponse(location);
    }

    public async Task<string?> GetResponseString(string url)
    {
        var httpResponse = await GetResponse(url);
        return httpResponse.Content;
    }

    private async Task<string> GetResponseInternal(string url)
    {
        FillHeaders();

        var uri = new Uri(url);
        _tlsClient.SetServerName(uri.Host);

        TlsClientProtocol? protocol = null;

        try
        {
            using var client = CreateTcpClient(uri.Host, 443, ProxyHost, ProxyPort);
            protocol = new TlsClientProtocol(client.GetStream());
            protocol.Connect(_tlsClient);

            var buildRequestBody = BuildRequestBody(url, uri.Host);
            var dataToSend = Encoding.UTF8.GetBytes(buildRequestBody);
            await protocol.Stream.WriteAsync(dataToSend);

            return ReadResponse(protocol.Stream);
        }
        finally
        {
            if (protocol != null)
            {
                protocol.Close();

                if (protocol.Stream != null)
                {
                    await protocol.Stream.DisposeAsync();
                }
            }
        }
    }

    private void FillHeaders()
    {
        if (!string.IsNullOrEmpty(UserAgent))
        {
            Headers.AddOrUpdate(HttpHeaderNames.UserAgent, UserAgent);
        }
    }

    private string ReadResponse(Stream stream)
    {
        using var sr = new StreamReader(stream);
        return sr.ReadToEnd();
    }

    private TcpClient CreateTcpClient(string host, int port, string? proxyHost = null, int? proxyPort = null)
    {
        if (string.IsNullOrEmpty(proxyHost) || proxyPort == null)
        {
            return new TcpClient(host, port);
        }

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Connect(proxyHost, proxyPort.Value);

        var connectMessage = Encoding.UTF8.GetBytes($"CONNECT {host}:{port} HTTP/1.1{Environment.NewLine}{Environment.NewLine}");
        socket.Send(connectMessage);

        var receiveBuffer = new byte[1024];
        var received = socket.Receive(receiveBuffer);

        var response = Encoding.UTF8.GetString(receiveBuffer, 0, received);
        if (!response.Contains("200"))
        {
            throw new Exception($"Ошибка подключения к прокси серверу {proxyHost}:{proxyPort}. Ответ: {response}");
        }

        return new TcpClient
        {
            Client = socket
        };
    }

    private string BuildRequestBody(string url, string hostName)
    {
        var hdr = new StringBuilder()
            .AppendLine($"{Method} {url} HTTP/1.1")
            .AppendLine($"Host: {hostName}")
            .AppendLine("Connection: close");

        foreach (var header in Headers)
        {
            hdr.AppendLine($"{header.Key}: {header.Value}");
        }

        var cookieString = Cookies
            .Select(x => $"{x.Name}={x.Value}")
            .ToList()
            .JoinToString("; ");

        hdr.AppendLine($"Cookie: {cookieString}");

        return hdr.AppendLine().ToString();
    }

}