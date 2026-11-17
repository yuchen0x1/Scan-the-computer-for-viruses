using System.Globalization;
using System.Resources;
using System.IO;

namespace PcSecurityCenter.App.Services;

/// UI-only locale selection. Product data, scan results, protocol values and
/// threat names remain unchanged; only the shell/catalog is localized here.
public static class LocalizationService
{
    private const string DefaultSetting = "auto";
    private static readonly ResourceManager Resources = new(
        "PcSecurityCenter.App.Resources.Strings",
        typeof(LocalizationService).Assembly);

    public static string Setting { get; private set; } = DefaultSetting;
    public static CultureInfo Culture { get; private set; } = CultureInfo.GetCultureInfo("zh-CN");

    public static void Initialize()
    {
        var saved = LoadSetting();
        SetSetting(saved, persist: false);
    }

    public static void SetSetting(string? setting, bool persist = true)
    {
        Setting = setting is "zh-CN" or "en-US" ? setting : DefaultSetting;
        Culture = ResolveCulture(Setting);
        CultureInfo.CurrentUICulture = Culture;
        if (persist) SaveSetting(Setting);
    }

    public static string Get(string key) => Resources.GetString(key, Culture) ?? key;

    private static CultureInfo ResolveCulture(string setting)
    {
        if (setting is "zh-CN" or "en-US") return CultureInfo.GetCultureInfo(setting);
        var system = CultureInfo.InstalledUICulture;
        return system.TwoLetterISOLanguageName.Equals("en", StringComparison.OrdinalIgnoreCase)
            ? CultureInfo.GetCultureInfo("en-US")
            : CultureInfo.GetCultureInfo("zh-CN");
    }

    private static string LoadSetting()
    {
        try
        {
            var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PcSecurityCenter", "locale.txt");
            return File.Exists(path) ? File.ReadAllText(path).Trim() : DefaultSetting;
        }
        catch { return DefaultSetting; }
    }

    private static void SaveSetting(string setting)
    {
        try
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PcSecurityCenter");
            Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, "locale.txt"), setting);
        }
        catch { /* read-only profile/private mode: keep the in-memory selection */ }
    }
}
