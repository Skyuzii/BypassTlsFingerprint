namespace BypassTlsFingerprint.Extensions;

internal static class ListExtensions
{
    public static string JoinToString(this List<string> list, string separator = ",")
    {
        return list == null || list.Count == 0
            ? null
            : string.Join(",", list);
    }

}