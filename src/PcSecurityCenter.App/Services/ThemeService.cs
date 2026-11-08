using System.Windows;
using System.Windows.Media;

namespace PcSecurityCenter.App.Services;

/// <summary>
/// 主题切换服务（亮色 / 暗色）。
///
/// 实现说明：WPF 会把 <c>Application.Resources</c> 中的画布对象冻结，
/// 因此不能就地修改 <c>SolidColorBrush.Color</c>。这里改用标准做法——
/// 把调色板做成两份资源字典（<c>Themes/Palette.Light.xaml</c> /
/// <c>Themes/Palette.Dark.xaml</c>），切换时替换合并字典；
/// 所有引用统一使用 <c>{DynamicResource BrushXxx}</c>，
/// 字典替换后 WPF 会自动重新求值，无需重建视觉树。
/// </summary>
public static class ThemeService
{
    private const string PaletteMarker = "Palette.";

    /// <summary>UI 是否使用亮色（白天）主题。默认亮色。</summary>
    public static bool IsLight { get; private set; } = true;

    public static event Action<bool>? ThemeChanged;

    /// <summary>应用指定主题（true=亮色）。可重复调用，无需重启。</summary>
    public static void Apply(bool light)
    {
        var app = Application.Current;
        if (app == null) return;

        var uri = new Uri(light ? "Themes/Palette.Light.xaml" : "Themes/Palette.Dark.xaml", UriKind.Relative);

        // 先移除旧调色板，再插入新调色板（置于首位，保证键优先解析）
        var merged = app.Resources.MergedDictionaries;
        for (var i = merged.Count - 1; i >= 0; i--)
        {
            var src = merged[i].Source?.OriginalString ?? string.Empty;
            if (src.Contains(PaletteMarker, StringComparison.OrdinalIgnoreCase))
                merged.RemoveAt(i);
        }
        merged.Insert(0, new ResourceDictionary { Source = uri });

        IsLight = light;
        ThemeChanged?.Invoke(light);
    }
}
