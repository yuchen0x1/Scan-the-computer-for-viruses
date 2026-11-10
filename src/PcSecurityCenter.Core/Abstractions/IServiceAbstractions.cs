using PcSecurityCenter.Core.Models;

namespace PcSecurityCenter.Core.Abstractions;

/// <summary>隔离区服务：受保护的隔离仓库（AES 加密 + SHA256 完整性校验 + 记录）。</summary>
public interface IQuarantineService
{
    Task<QuarantineEntry> QuarantineFileAsync(string filePath, string reason, string engine, ThreatSeverity severity);
    Task<List<QuarantineEntry>> ListAsync();
    Task<bool> RestoreAsync(Guid entryId, string? restoreDir = null);
    Task<bool> DeleteAsync(Guid entryId);
    string VaultDirectory { get; }
}

/// <summary>系统安全检查服务。</summary>
public interface ISecurityCheckService
{
    Task<List<SecurityCheckItem>> RunAllChecksAsync(CancellationToken ct = default);
    SecurityScore CalculateScore(IReadOnlyList<SecurityCheckItem> checks);
}

/// <summary>评分计算器（独立出来便于单元测试；评分规则公开透明）。</summary>
public interface IScoreCalculator
{
    SecurityScore FromChecks(IReadOnlyList<SecurityCheckItem> checks);
}

/// <summary>性能监控服务。</summary>
public interface IPerformanceMonitor
{
    bool IsRunning { get; }
    Task<SystemHardwareInfo> GetHardwareInfoAsync(CancellationToken ct = default);
    Task<PerformanceSnapshot> SampleAsync(CancellationToken ct = default);
    void SetIntervalMs(int intervalMs);
    event EventHandler<PerformanceSnapshot>? Sampled;
    void Start();
    void Stop();
}

/// <summary>网络监控服务。</summary>
public interface INetworkMonitor
{
    Task<List<NetworkAdapterInfo>> GetAdaptersAsync(CancellationToken ct = default);
    Task<List<TcpConnectionInfo>> GetTcpConnectionsAsync(CancellationToken ct = default);
    Task<List<FirewallProfileInfo>> GetFirewallProfilesAsync(CancellationToken ct = default);
    Task<(string ProxyServer, string ProxyOverride, bool ProxyEnabled)> GetProxyAsync();
    Task<HostsFileReport> InspectHostsFileAsync();
    Task<List<string>> GetDnsServersAsync();
    Task FlushDnsAsync();
    Task<NetworkTrafficInfo> GetTotalTrafficSampleAsync();
}

/// <summary>Hosts 文件检查报告。</summary>
public class HostsFileReport
{
    public string FilePath { get; set; } = string.Empty;
    public int TotalEntries { get; set; }
    public int ActiveRedirects { get; set; }
    public List<string> NonLocalRedirects { get; set; } = new();
    public bool FileLockedByOther { get; set; }
    public string RawContent { get; set; } = string.Empty;
}

/// <summary>启动项管理。</summary>
public interface IStartupManager
{
    Task<List<StartupItem>> EnumerateAsync(CancellationToken ct = default);
    /// <summary>启用/禁用启动项（返回是否成功；操作会记录日志）。</summary>
    Task<bool> SetEnabledAsync(StartupItem item, bool enabled);
}

/// <summary>已安装软件枚举。</summary>
public interface IInstalledAppsProvider
{
    Task<List<InstalledAppInfo>> EnumerateAsync(CancellationToken ct = default);
    Task<List<ScheduledTaskInfo>> GetScheduledTasksAsync(CancellationToken ct = default);
    Task<List<ServiceInfo>> GetServicesAsync(CancellationToken ct = default);
}

/// <summary>系统维护服务。</summary>
public interface IMaintenanceService
{
    Task<List<MaintenanceCleanItem>> ScanCleanableAsync(CancellationToken ct = default);
    Task<(long FreedBytes, int FilesRemoved)> CleanAsync(IEnumerable<MaintenanceCleanItem> items, CancellationToken ct = default);
    Task<List<DiskSpaceItem>> AnalyzeDiskSpaceAsync(string driveRoot, CancellationToken ct = default);
    Task<(bool Success, string Output)> RunSfcVerifyAsync(CancellationToken ct = default);
    Task<(bool Success, string Output)> RunDismScanHealthAsync(CancellationToken ct = default);
    Task<(bool Success, string Output)> RunChkdskReadOnlyAsync(string drive, CancellationToken ct = default);
    Task<List<RestorePointInfo>> GetRestorePointsAsync(CancellationToken ct = default);
    Task<(bool Success, string Output)> CreateRestorePointAsync(string description, CancellationToken ct = default);
}

/// <summary>文件分析服务。</summary>
public interface IFileAnalysisService
{
    Task<FileAnalysisReport> AnalyzeAsync(string filePath, CancellationToken ct = default);
    /// <summary>计算文件 SHA256（流式）。</summary>
    Task<string> ComputeSha256Async(string filePath, CancellationToken ct = default);
}

/// <summary>实时防护服务（事件驱动 + 低频轮询，控制资源占用）。</summary>
public interface IRealtimeProtector : IDisposable
{
    bool IsRunning { get; }
    void Start();
    void Stop();
    event EventHandler<SecurityEvent>? EventRaised;
    List<SecurityEvent> RecentEvents { get; }
}

/// <summary>事件总线 + 持久化。</summary>
public interface ISecurityEventService
{
    Task PublishAsync(SecurityEvent evt);
    event EventHandler<SecurityEvent>? EventPublished;
    Task<List<SecurityEvent>> GetRecentAsync(int count = 50);
}

/// <summary>权限服务：管理员检测与受控提权。</summary>
public interface IPermissionService
{
    bool IsElevated { get; }
    /// <summary>以管理员身份运行一段受白名单约束的操作脚本；返回 (成功, 输出)。
    /// 只有确认子进程已获得管理员权限且脚本成功时才返回 true；用户取消 UAC、提权未生效、
    /// 结果不可读等情况一律返回 false 并给出可解释原因。</summary>
    Task<(bool Success, string Output)> RunElevatedAsync(
        ElevatedOperation op,
        IReadOnlyDictionary<string, string>? args = null,
        CancellationToken ct = default);
    /// <summary>当前进程是否以管理员运行（用于 UI 提示）。</summary>
    string ElevationHint { get; }
}

/// <summary>允许的提权操作白名单。每一项都有固定的脚本模板，参数仅做受控替换。</summary>
public enum ElevatedOperation
{
    CreateRestorePoint,
    RunSfcVerifyOnly,
    RunDismScanHealth,
    RunChkdskReadOnly,
    DisableScheduledTask,
    EnableScheduledTask,
    DisableService,
    EnableService,
}

/// <summary>报告导出。</summary>
public interface IReportExporter
{
    Task<string> ExportHtmlAsync(string outputPath);
    Task<string> ExportPdfAsync(string outputPath);
}

/// <summary>应用通知（应用内 Toast + 事件）。</summary>
public interface INotificationService
{
    void Notify(string title, string message, ThreatSeverity severity = ThreatSeverity.Info);
    event EventHandler<(string Title, string Message, ThreatSeverity Severity)>? Notified;
}

/// <summary>配置服务。</summary>
public interface IConfigService
{
    AppConfigData Current { get; }
    Task SaveAsync();
    Task LoadAsync();
}
