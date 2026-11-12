namespace PcSecurityCenter.Core.Models;

/// <summary>应用配置（JSON 持久化）。仅包含应用自身行为偏好，不收集任何隐私数据。</summary>
public class AppConfigData
{
    public string AppVersion { get; set; } = "1.2.2";
    public int PerformanceIntervalMs { get; set; } = 2000;
    public int RealtimePollIntervalSec { get; set; } = 15;
    public bool RealtimeEnabled { get; set; } = true;
    public bool AutoUpdateDefenderSignatures { get; set; } = false;
    /// <summary>哈希信誉查询需要用户显式同意并配置 API，默认关闭。</summary>
    public bool HashLookupEnabled { get; set; } = false;
    public string? HashLookupApiKey { get; set; }
    public int MaxLogDays { get; set; } = 30;
    /// <summary>界面主题：true=亮色（白天，默认），false=暗色。设置后持久化，重启保持。</summary>
    public bool UseLightTheme { get; set; } = true;
    public string ScanExclusions { get; set; } = string.Empty;
    public bool FirstRunCompleted { get; set; } = false;
    public DateTime LastFullScanTime { get; set; }
    public DateTime LastQuickScanTime { get; set; }
    public DateTime LastHealthCheckTime { get; set; }
    public int LastSecurityScore { get; set; } = -1;
}
