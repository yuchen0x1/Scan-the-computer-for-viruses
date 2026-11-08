using System.Text.Json.Serialization;

namespace PcSecurityCenter.Core.Models;

/// <summary>CPU 快照。</summary>
public class CpuInfo
{
    public string Name { get; set; } = string.Empty;
    public int PhysicalCores { get; set; }
    public int LogicalCores { get; set; }
    public double UsagePercent { get; set; }
    public double? TemperatureC { get; set; }
    public string? MaxClockMHz { get; set; }
}

/// <summary>GPU 快照。</summary>
public class GpuInfo
{
    public string Name { get; set; } = string.Empty;
    /// <summary>使用率百分比；null 表示当前环境无法读取（不虚构数据）。</summary>
    public double? UsagePercent { get; set; }
    /// <summary>显存总量（字节）；null 表示无法读取。</summary>
    public ulong? MemoryTotalBytes { get; set; }
    public ulong? MemoryUsedBytes { get; set; }
    public string Source { get; set; } = string.Empty;
}

/// <summary>内存快照。</summary>
public class MemoryInfo
{
    public ulong TotalBytes { get; set; }
    public ulong UsedBytes { get; set; }
    public ulong AvailableBytes { get; set; }
    public double UsagePercent => TotalBytes > 0 ? UsedBytes * 100.0 / TotalBytes : 0;
}

/// <summary>磁盘快照。</summary>
public class DiskInfo
{
    public string DriveLetter { get; set; } = string.Empty;
    public string VolumeLabel { get; set; } = string.Empty;
    public ulong TotalBytes { get; set; }
    public ulong FreeBytes { get; set; }
    public double UsedPercent => TotalBytes > 0 ? (TotalBytes - FreeBytes) * 100.0 / TotalBytes : 0;
    /// <summary>读速率（字节/秒）。</summary>
    public double ReadBytesPerSec { get; set; }
    /// <summary>写速率（字节/秒）。</summary>
    public double WriteBytesPerSec { get; set; }
    public string Model { get; set; } = string.Empty;
    public string MediaType { get; set; } = string.Empty;
    public string TotalBytesHuman => PcSecurityCenter.Core.Utils.SizeFormat.Format((long)TotalBytes);
    public string FreeBytesHuman => PcSecurityCenter.Core.Utils.SizeFormat.Format((long)FreeBytes);
}

/// <summary>网络适配器流量快照。</summary>
public class NetworkTrafficInfo
{
    public string AdapterName { get; set; } = string.Empty;
    public double UploadBytesPerSec { get; set; }
    public double DownloadBytesPerSec { get; set; }
    public double TotalUploadBytesPerSec => UploadBytesPerSec;
    public double TotalDownloadBytesPerSec => DownloadBytesPerSec;
}

/// <summary>一次性能采样快照。</summary>
public class PerformanceSnapshot
{
    public DateTime Timestamp { get; set; } = DateTime.Now;
    public CpuInfo Cpu { get; set; } = new();
    public MemoryInfo Memory { get; set; } = new();
    public GpuInfo Gpu { get; set; } = new();
    public List<DiskInfo> Disks { get; set; } = new();
    public List<NetworkTrafficInfo> Networks { get; set; } = new();
}

/// <summary>静态硬件/系统信息。</summary>
public class SystemHardwareInfo
{
    public string MachineName { get; set; } = string.Empty;
    public string OsName { get; set; } = string.Empty;
    public string OsVersion { get; set; } = string.Empty;
    public string OsBuild { get; set; } = string.Empty;
    public bool Is64Bit { get; set; }
    public string CpuName { get; set; } = string.Empty;
    public List<string> GpuNames { get; set; } = new();
    public ulong MemoryTotalBytes { get; set; }
    public List<DiskInfo> Disks { get; set; } = new();
    public DateTime BootTime { get; set; }
}

/// <summary>TCP 连接信息。</summary>
public class TcpConnectionInfo
{
    public string LocalAddress { get; set; } = string.Empty;
    public ushort LocalPort { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public ushort RemotePort { get; set; }
    public string State { get; set; } = string.Empty;
    public int ProcessId { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string ProcessPath { get; set; } = string.Empty;
    public bool IsSigned { get; set; }
    public bool IsSuspicious { get; set; }
    public string SuspiciousReason { get; set; } = string.Empty;
}

/// <summary>网络适配器详细信息。</summary>
public class NetworkAdapterInfo
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public List<string> IpAddresses { get; set; } = new();
    public string Gateway { get; set; } = string.Empty;
    public List<string> DnsServers { get; set; } = new();
    public ulong BytesSent { get; set; }
    public ulong BytesReceived { get; set; }
    public bool IsVirtual { get; set; }
}

/// <summary>防火墙配置文件状态。</summary>
public class FirewallProfileInfo
{
    public string ProfileName { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public string InboundAction { get; set; } = string.Empty;
    public string OutboundAction { get; set; } = string.Empty;
}

/// <summary>启动项条目。</summary>
public class StartupItem
{
    public string Name { get; set; } = string.Empty;
    public string Command { get; set; } = string.Empty;
    /// <summary>来源位置（注册表键/启动文件夹/任务路径/服务名）。</summary>
    public string Location { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public string Publisher { get; set; } = string.Empty;
    public bool IsSigned { get; set; }
    public bool IsMicrosoft { get; set; }
    public ThreatSeverity RiskLevel { get; set; } = ThreatSeverity.Info;
    public string RiskNote { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public string EnabledText => Enabled ? "启用" : "已禁用";
    public string ToggleText => Enabled ? "禁用" : "启用";
    public string RiskText => string.IsNullOrEmpty(RiskNote) ? "—" : RiskNote;
    public StartupItem Clone() => (StartupItem)MemberwiseClone();
}

/// <summary>已安装软件。</summary>
public class InstalledAppInfo
{
    public string DisplayName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    public string InstallLocation { get; set; } = string.Empty;
    public string UninstallString { get; set; } = string.Empty;
    public string InstallDate { get; set; } = string.Empty;
    public ulong? EstimatedSizeKb { get; set; }
    public bool IsSigned { get; set; }
    public bool IsMicrosoft { get; set; }
    public string RegistryKey { get; set; } = string.Empty;
    public ThreatSeverity RiskLevel { get; set; } = ThreatSeverity.Info;
    public string RiskNote { get; set; } = string.Empty;
}

/// <summary>Windows 服务信息。</summary>
public class ServiceInfo
{
    public string Name { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string StartMode { get; set; } = string.Empty;
    public string ExePath { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

/// <summary>计划任务信息。</summary>
public class ScheduledTaskInfo
{
    public string Path { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string Author { get; set; } = string.Empty;
    public ThreatSeverity RiskLevel { get; set; } = ThreatSeverity.Info;
    public string RiskNote { get; set; } = string.Empty;
    public bool Enabled { get; set; }
}

/// <summary>维护项（可清理内容）。</summary>
public class MaintenanceCleanItem
{
    public required string Id { get; init; }
    public required string Name { get; set; }
    public required string Description { get; set; }
    public long SizeBytes { get; set; }
    public int FileCount { get; set; }
    public List<string> SampleFiles { get; set; } = new();
    public bool Selected { get; set; } = true;
    public bool RequiresAdmin { get; set; }
    public string SizeBytesHuman => PcSecurityCenter.Core.Utils.SizeFormat.Format(SizeBytes);
}

/// <summary>文件分析报告。</summary>
public class FileAnalysisReport
{
    public string FilePath { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public string Sha1 { get; set; } = string.Empty;
    public string Md5 { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime ModifiedAt { get; set; }
    public string FileTypeName { get; set; } = string.Empty;
    public double EntropyBitsPerByte { get; set; }
    public bool IsPe { get; set; }
    public string? PeMachine { get; set; }
    public bool? PeIsSigned { get; set; }
    public string? SignatureSubject { get; set; }
    public string? SignatureStatus { get; set; }
    public string? SignaturePublisher { get; set; }
    public List<string> PeImports { get; set; } = new();
    public List<string> Indicators { get; set; } = new();
    public ThreatSeverity RiskLevel { get; set; } = ThreatSeverity.Info;
    public string RiskSummary { get; set; } = string.Empty;
    public string? HashLookupNote { get; set; }
}

/// <summary>隔离区条目。</summary>
public class QuarantineEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string OriginalPath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public string OriginalSha256 { get; set; } = string.Empty;
    public string VaultFileName { get; set; } = string.Empty;
    public DateTime QuarantinedAt { get; set; }
    public string Reason { get; set; } = string.Empty;
    public string Engine { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; }
}

/// <summary>磁盘空间分析条目。</summary>
public class DiskSpaceItem
{
    public string Path { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public int FileCount { get; set; }
}

/// <summary>系统还原点信息。</summary>
public class RestorePointInfo
{
    public int SequenceNumber { get; set; }
    public string Description { get; set; } = string.Empty;
    public DateTime CreationTime { get; set; }
    public string Type { get; set; } = string.Empty;
}
