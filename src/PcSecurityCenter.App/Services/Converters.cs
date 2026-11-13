using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace PcSecurityCenter.App.Services;

/// <summary>bool 取反（用于两个 RadioButton 绑定同一个布尔属性的两面）。</summary>
public class InverseBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is bool b ? !b : false;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is bool b ? !b : false;
}

/// <summary>字符串非空 → Visible。</summary>
public class NotEmptyToVisibleConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => string.IsNullOrWhiteSpace(value as string) ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => Binding.DoNothing;
}

/// <summary>bool → Visibility（true 显示）。</summary>
public class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is true ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is Visibility.Visible;
}

/// <summary>扫描表格中的原生中文标签，避免枚举英文被窄列截断。</summary>
public class ThreatLabelConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value switch
    {
        Core.Models.ThreatSeverity.Info => "提示", Core.Models.ThreatSeverity.Low => "低",
        Core.Models.ThreatSeverity.Medium => "中", Core.Models.ThreatSeverity.High => "高", Core.Models.ThreatSeverity.Critical => "严重",
        Core.Models.DetectionKind.Confirmed => "确认威胁", Core.Models.DetectionKind.Suspicious => "可疑", Core.Models.DetectionKind.Notice => "提示",
        Core.Models.ThreatStatus.Active => "待处理", Core.Models.ThreatStatus.Quarantined => "已隔离", Core.Models.ThreatStatus.Removed => "已删除",
        Core.Models.ThreatStatus.Ignored => "已忽略", Core.Models.ThreatStatus.Allowed => "已允许", Core.Models.ThreatStatus.Fixed => "已修复", Core.Models.ThreatStatus.Failed => "失败",
        "MicrosoftDefender" => "Defender", "SmartRisk" => "风险规则", _ => value?.ToString() ?? ""
    };
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => Binding.DoNothing;
}
