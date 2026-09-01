using System.Net;
using System.Net.Sockets;
using System.Text;

using BypassTlsFingerprint.Abstractions;
using BypassTlsFingerprint.Implementations.Constants;
using BypassTlsFingerprint.Implementations.Extensions;
using BypassTlsFingerprint.Implementations.Models;
using BypassTlsFingerprint.Implementations.Parsers;

using Org.BouncyCastle.Tls;

namespace BypassTlsFingerprint.Implementations;

public sealed class BypassHttpClient
{
    private readonly BrowserTlsClient _tlsClient;
    private readonly HttpParser _httpParser = new HttpParser();

    public bool DisableRedirect { get; set; }
    public HttpMethod Method { get; set; } = HttpMethod.Get;

    public CookieCollection Cookies { get; set; } = new CookieCollection();

    public string? ProxyHost { get; set; }

    public int? ProxyPort { get; set; }

    public string UserAgent { get; set; }

    public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();


    public BypassHttpClient(BrowserTlsClient tlsClient)
    {
        _tlsClient = tlsClient;
    }

    public async Task<HttpResponse> GetResponse(string url)
    {
        string response = await GetResponseInternal(url);
        HttpResponse httpResponse = await _httpParser.ParseHttpResponse(response);

        foreach (Cookie cookie in httpResponse.Cookies)
        {
            Cookies.Add(cookie);
        }

        if (DisableRedirect || !httpResponse.Headers.TryGetValue("Location", out string? location))
        {
            return httpResponse;
        }

        return await GetResponse(location);
    }

    public async Task<string?> GetResponseString(string url)
    {
        HttpResponse httpResponse = await GetResponse(url);
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
            using TcpClient client = CreateTcpClient(uri.Host, port: 443, ProxyHost, ProxyPort);
            protocol = new TlsClientProtocol(client.GetStream());
            protocol.Connect(_tlsClient);

            string buildRequestBody = BuildRequestBody(url, uri.Host);
            byte[] dataToSend = Encoding.UTF8.GetBytes(buildRequestBody);
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

        byte[] connectMessage = Encoding.UTF8.GetBytes($"CONNECT {host}:{port} HTTP/1.1{Environment.NewLine}{Environment.NewLine}");
        socket.Send(connectMessage);

        var receiveBuffer = new byte[1024];
        int received = socket.Receive(receiveBuffer);

        string response = Encoding.UTF8.GetString(receiveBuffer, index: 0, received);
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
        StringBuilder hdr = new StringBuilder()
            .AppendLine($"{Method} {url} HTTP/1.1")
            .AppendLine($"Host: {hostName}")
            .AppendLine("Connection: close");

        foreach (KeyValuePair<string, string> header in Headers)
        {
            hdr.AppendLine($"{header.Key}: {header.Value}");
        }

        string cookieString = Cookies
            .Select(x => $"{x.Name}={x.Value}")
            .ToList()
            .JoinToString("; ");

        hdr.AppendLine($"Cookie: {cookieString}");

        return hdr.AppendLine().ToString();
    }

}