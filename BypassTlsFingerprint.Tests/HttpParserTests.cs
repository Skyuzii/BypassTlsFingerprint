using BypassTlsFingerprint.Parsers;

namespace BypassTlsFingerprint.Tests;

internal sealed class HttpParserTests
{
    [Test]
    public async Task ParseHttpResponse_ShouldCorrectParse()
    {
        var response = @"HTTP/1.1 302 Moved Temporarily
Server: nginx
Date: Tue, 20 Sep 2022 22:59:54 GMT
Content-Type: text/html
Content-Length: 138
Connection: close
Location: https://auto.ru/showcaptcha?cc=1&mt=EF46349789166EF33EFCB7561A2F3B5955C6D79F0BA70CA9B7428B21D8291350&retpath=aHR0cHM6Ly9hdXRvLnJ1L2NhcnMvdXNlZD8%2C_2d711b9c2cb461bd3a01ee2a3f4de09e&t=2/1663714794/dd0ebcd6249ead696826b4a07790ab2f&u=8e901059-1a1452db-d7aa05ef-706172a5&s=a0ffc248bda7a7e11eff9ce203d026f5
Set-Cookie: spravka=dD0xNjMyMTc4Nzk0O2k9MTg1LjEyNy4yMjUuMTY5O0Q9NzMyMTZENTkxOTA2MDlFNDBFMjNDRTk2MzNFNjA3ODZFMzgxMUJBOTNDNkM2OUQ4Nzc3QUFDNTNDNTY0NTFDMEMzQjBBODJEO3U9MTYzMjE3ODc5NDI0MTY0MjIyNTtoPTg2N2M2OTdjYzdiMTliODdjZGRjYTZiNzE5Mjc5MTIz; domain=.auto.ru; path=/; expires=Thu, 20-Oct-2022 22:59:54 GMT
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
X-Upstream-Addr: [::1]:1111
X-LB-Host: lb-01-vla.prod.vertis.yandex.net
X-Request-Id: 8d03dd8c0eaaceb537d63b8c3bbe0f85
X-UA-Bot: 1

<html>
<head><title>302 Found</title></head>
<body>
<center><h1>302 Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
";

        var httpParser = new HttpParser();
        var httpResponse = await httpParser.ParseHttpResponse(response);
        Assert.That(httpResponse.StatusCode > 0, Is.True);
        Assert.That(httpResponse.Content != null, Is.True);
        Assert.That(httpResponse.HttpVersion != null, Is.True);
        Assert.That(httpResponse.Cookies.Count > 0, Is.True);
    }

}