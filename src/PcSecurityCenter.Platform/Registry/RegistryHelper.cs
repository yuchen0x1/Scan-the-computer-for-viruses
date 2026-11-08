using Microsoft.Win32;

namespace PcSecurityCenter.Platform.WinRegistry;

/// <summary>注册表只读/受控写入助手。所有写入必须带日志，且仅限启动项管理等白名单场景。</summary>
public static class RegistryHelper
{
    public static string? ReadString(RegistryKey hive, string subKey, string valueName)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey, writable: false);
            return key?.GetValue(valueName) as string;
        }
        catch (Exception) { return null; }
    }

    public static int? ReadInt(RegistryKey hive, string subKey, string valueName)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey, writable: false);
            var v = key?.GetValue(valueName);
            return v switch { int i => i, long l => (int)l, _ => null };
        }
        catch (Exception) { return null; }
    }

    public static string[] GetValueNames(RegistryKey hive, string subKey)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey, writable: false);
            return key?.GetValueNames() ?? Array.Empty<string>();
        }
        catch (Exception) { return Array.Empty<string>(); }
    }

    public static string? GetStringValue(RegistryKey hive, string subKey, string valueName)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey, writable: false);
            return key?.GetValue(valueName, null) switch
            {
                string s => s,
                null => null,
                var o => o.ToString(),
            };
        }
        catch (Exception) { return null; }
    }

    /// <summary>写注册表值（启动项禁用=改名等操作）。调用方必须记录日志。</summary>
    public static bool WriteValue(RegistryKey hive, string subKey, string valueName, object value)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey, writable: true);
            if (key == null) return false;
            key.SetValue(valueName, value);
            return true;
        }
        catch (Exception) { return false; }
    }

    public static bool DeleteValue(RegistryKey hive, string subKey, string valueName)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey, writable: true);
            if (key == null) return false;
            key.DeleteValue(valueName, throwOnMissingValue: false);
            return true;
        }
        catch (Exception) { return false; }
    }

    public static bool RenameValue(RegistryKey hive, string subKey, string oldName, string newName)
    {
        try
        {
            using var key = hive.OpenSubKey(subKey, writable: true);
            if (key == null) return false;
            var val = key.GetValue(oldName);
            if (val == null) return false;
            key.SetValue(newName, val);
            key.DeleteValue(oldName, false);
            return true;
        }
        catch (Exception) { return false; }
    }
}
