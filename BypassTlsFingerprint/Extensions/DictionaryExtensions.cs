namespace BypassTlsFingerprint.Extensions;

internal static class DictionaryExtensions
{
    public static void AddOrUpdate<T1, T2>(this Dictionary<T1, T2> dic, T1 key, T2 value) where T1 : notnull
    {
        if (dic.ContainsKey(key))
        {
            dic[key] = value;
            return;
        }

        dic.Add(key, value);
    }
}
