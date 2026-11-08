using System.Threading.Channels;
using PcSecurityCenter.Core.Models;

namespace PcSecurityCenter.Core.Abstractions;

/// <summary>Microsoft Defender 官方接口封装（PowerShell cmdlet / MpCmdRun / WMI）。</summary>
public interface IDefenderClient
{
    /// <summary>Defender 是否安装且引擎可用。</summary>
    bool IsAvailable { get; }
    Task<DefenderStatusInfo> GetStatusAsync(CancellationToken ct = default);
    Task<bool> UpdateSignaturesAsync(CancellationToken ct = default);
    /// <summary>启动 Defender 原生快速扫描（后台执行，完成后可查询结果）。</summary>
    Task<bool> StartQuickScanAsync(CancellationToken ct = default);
    /// <summary>对指定文件/目录执行 MpCmdRun 自定义扫描，返回真实结论。</summary>
    Task<MpScanResult> ScanPathsAsync(IEnumerable<string> paths, CancellationToken ct);
    /// <summary>查询真实威胁检测记录。</summary>
    Task<List<ThreatInfo>> GetThreatDetectionsAsync(CancellationToken ct = default);
    /// <summary>通过官方接口处理威胁（隔离/清除检测到的活动威胁）。</summary>
    Task<bool> RemoveThreatsAsync(CancellationToken ct = default);
    /// <summary>停止正在进行的引擎扫描（MSFT_MpScan.Stop / 进程终止）。</summary>
    Task StopScanAsync(CancellationToken ct = default);
    /// <summary>
    /// 流式逐目录扫描：从目录通道读取目录，逐个交给 Defender 引擎扫描，
    /// 每完成一个目录输出一条真实结果（文件数 + 新检出）。读取阻塞即引擎空闲，
    /// 从而天然支持暂停/恢复（由写入端通过暂停门控制）。
    /// </summary>
    IAsyncEnumerable<DirectoryScanResult> StreamScanDirectoriesAsync(
        ChannelReader<string> directories, CancellationToken ct);
    /// <summary>MpCmdRun.exe 路径；不可用时为 null。</summary>
    string? MpCmdRunPath { get; }
}

/// <summary>Defender 状态信息。</summary>
public class DefenderStatusInfo
{
    public bool Installed { get; set; }
    public bool EngineAvailable { get; set; }
    public bool RealTimeProtection { get; set; }
    public bool AntivirusEnabled { get; set; }
    public bool BehaviorMonitor { get; set; }
    public DateTime? SignatureLastUpdated { get; set; }
    public string SignatureVersion { get; set; } = string.Empty;
    public DateTime? LastQuickScan { get; set; }
    public DateTime? LastFullScan { get; set; }
    public int QuickScanAgeDays { get; set; }
    public string ErrorNote { get; set; } = string.Empty;
}

/// <summary>MpCmdRun 扫描结果。</summary>
public class MpScanResult
{
    public bool Success { get; set; }
    public int ExitCode { get; set; }
    /// <summary>引擎报告的威胁数（真实输出解析）。</summary>
    public int ThreatsFound { get; set; }
    public List<string> ThreatList { get; set; } = new();
    public string RawOutputTail { get; set; } = string.Empty;
    public string Error { get; set; } = string.Empty;
}

/// <summary>通用扫描引擎接口。可扩展接入其他引擎（如 YARA）。</summary>
public interface IScanEngine
{
    /// <summary>引擎唯一名称。</summary>
    string Name { get; }
    /// <summary>引擎是否可用。</summary>
    bool IsAvailable { get; }
    /// <summary>对一组文件执行检测。实现方必须是真实检测，不得返回伪造结果。</summary>
    IAsyncEnumerable<ThreatInfo> ScanFilesAsync(
        IReadOnlyList<string> files,
        ScanContext context,
        CancellationToken ct);
}

/// <summary>单目录引擎扫描结果（真实输出）。</summary>
public class DirectoryScanResult
{
    public string Directory { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string Error { get; set; } = string.Empty;
    public int FileCount { get; set; }
    public double Seconds { get; set; }
    public List<ThreatInfo> NewDetections { get; set; } = new();
}

/// <summary>扫描上下文。</summary>
public class ScanContext
{
    public ScanType Type { get; init; }
    public Guid ScanRunId { get; init; }
    public IReadOnlyList<string> RootPaths { get; init; } = Array.Empty<string>();
}

/// <summary>扫描编排器：统一调度范围枚举、多引擎、暂停/恢复/取消、进度与记录。</summary>
public interface IScanOrchestrator
{
    ScanProgress CurrentProgress { get; }
    event EventHandler<ScanProgress>? ProgressChanged;
    event EventHandler<ThreatInfo>? ThreatFound;
    event EventHandler<ScanProgress>? Completed;
    Task StartAsync(ScanRequest request);
    void Pause();
    void Resume();
    Task CancelAsync();
}

/// <summary>扫描请求。</summary>
public class ScanRequest
{
    public ScanType Type { get; init; }
    public List<string> RootPaths { get; init; } = new();
    /// <summary>全盘扫描包含的驱动器。</summary>
    public List<string> Drives { get; init; } = new();
}

/// <summary>扫描范围构建器：根据扫描类型给出真实、可解释的扫描范围。</summary>
public interface IScanRangeBuilder
{
    /// <summary>快速扫描范围：启动相关目录、临时目录、下载目录、常见驻留位置。</summary>
    List<string> BuildQuickRange();
    /// <summary>全盘扫描范围：本地固定驱动器（可过滤）。</summary>
    List<string> BuildFullRange(IEnumerable<string>? drives = null);
    /// <summary>获取范围中预计的文件数量（尽力估算）。</summary>
    Task<long> EstimateFileCountAsync(IEnumerable<string> roots, CancellationToken ct);
}
