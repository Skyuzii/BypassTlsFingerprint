using System.Net;

using BypassTlsFingerprint.Implementations.Extensions;
using BypassTlsFingerprint.Implementations.Models;

namespace BypassTlsFingerprint.Implementations.Parsers;

public sealed class HttpParser
{
    public async Task<HttpResponse> ParseHttpResponse(string responseString)
    {
        string? line = null;
        var mode = ParseMode.FirstLine;
        var httpResponse = new HttpResponse();

        using var reader = new StringReader(responseString);
        while ((line = await reader.ReadLineAsync()) != null)
        {
            switch (mode)
            {
                case ParseMode.FirstLine:
                    ParseFirstLine(httpResponse, line, ref mode);
                    break;
                case ParseMode.Headers:
                    ParseHeader(httpResponse, line, ref mode);
                    break;
                case ParseMode.Body:
                    await ParseBody(httpResponse, line, reader);
                    break;
            }
        }

        return httpResponse;
    }

    private void ParseFirstLine(HttpResponse httpResponse, string line, ref ParseMode mode)
    {
        string[] args = line.Split(' ');
        if (args.Length < 3)
        {
            throw new ArgumentException("line не содержит правльниую первую строку HTTP request");
        }

        httpResponse.HttpVersion = args[0];
        httpResponse.StatusCode = int.Parse(args[1]);

        mode = ParseMode.Headers;
    }

    private void ParseHeader(HttpResponse httpResponse, string line, ref ParseMode mode)
    {
        if (string.IsNullOrEmpty(line))
        {
            mode = ParseMode.Body;
            return;
        }

        int splitIndexOf = line.IndexOf(": ", StringComparison.Ordinal);
        if (splitIndexOf < 1)
        {
            throw new ArgumentException($"Ответ содержит некорректный заголовок - {line}");
        }

        string headerName = line.Substring(startIndex: 0, splitIndexOf);
        string headerValue = line.Substring(splitIndexOf + 1);
        httpResponse.Headers.AddOrUpdate(headerName, headerValue);

        if (headerName == "Set-Cookie")
        {
            ParseCookie(httpResponse, headerValue);
        }
    }

    private void ParseCookie(HttpResponse httpResponse, string headerValue)
    {
        string[] args = headerValue.Split(';');
        var cookie = new Cookie { Path = "/" };

        for (var i = 0; i < 2; i++)
        {
            string item = args[i];
            int splitIndexOf = item.IndexOf("=", StringComparison.Ordinal);
            if (splitIndexOf < 1)
            {
                throw new ArgumentException($"Куки содержит некорректный заголовок - {headerValue}");
            }

            string name = item.Substring(startIndex: 0, splitIndexOf).TrimStart();
            string value = item.Substring(splitIndexOf + 1);

            switch (name)
            {
                case "domain":
                    cookie.Domain = value;
                    break;
                case "path":
                    cookie.Path = value;
                    break;
                default:
                    cookie.Name = name;
                    cookie.Value = value;
                    break;
            }
        }

        httpResponse.Cookies.Add(cookie);
    }

    private async Task ParseBody(HttpResponse httpResponse, string line, StringReader reader)
    {
        httpResponse.Content = $"{line}\r\n{await reader.ReadToEndAsync()}";
    }

    private enum ParseMode
    {
        FirstLine,
        Headers,
        Body
    }

}