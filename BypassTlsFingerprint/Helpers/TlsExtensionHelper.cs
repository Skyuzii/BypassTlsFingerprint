using System.Text;

namespace BypassTlsFingerprint.Helpers;

internal static class TlsExtensionHelper
{
    public static byte[] GetServerNameExtension(string serverName)
    {
        var name = Encoding.ASCII.GetBytes(serverName);
        var ext = new byte[5 + name.Length];
        ext[0] = 0;
        ext[1] = (byte) (3 + name.Length);
        ext[2] = 0;
        ext[3] = 0;
        ext[4] = (byte) name.Length;
        for (int i = 5, j = 0; i < ext.Length; i++, j++)
        {
            ext[i] = name[j];
        }

        return ext;
    }
}