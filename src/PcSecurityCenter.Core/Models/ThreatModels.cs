namespace PcSecurityCenter.Core.Models;

/// <summary>威胁/风险严重级别。</summary>
public enum ThreatSeverity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>威胁处理状态。</summary>
public enum ThreatStatus
{
    Active,
    Quarantined,
    Removed,
    Ignored,
    Allowed,
    Fixed,
    Failed,
}

/// <summary>检测结论的类型：确定威胁 / 可疑风险 / 提示信息。引擎不得在证据不足时给出确定威胁。</summary>
public enum DetectionKind
{
    /// <summary>有明确检测依据的威胁（如 Defender 检出）。</summary>
    Confirmed,
    /// <summary>基于规则的疑似风险（如启动目录中的可疑脚本），需要用户判断。</summary>
    Suspicious,
    /// <summary>提示信息（如签名缺失），不一定是恶意。</summary>
    Notice,
}

/// <summary>单个威胁条目。</summary>
public class ThreatInfo
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Low;
    public DetectionKind Kind { get; set; } = DetectionKind.Suspicious;
    public string FilePath { get; set; } = string.Empty;
    /// <summary>检测引擎标识，如 "MicrosoftDefender" / "SmartRisk"。</summary>
    public string Engine { get; set; } = string.Empty;
    /// <summary>检测依据（命中规则、威胁 ID、启发式说明等），必须可追溯。</summary>
    public string Evidence { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; } = DateTime.Now;
    public string Sha256 { get; set; } = string.Empty;
    public ThreatStatus Status { get; set; } = ThreatStatus.Active;
    public string Recommendation { get; set; } = string.Empty;
    /// <summary>关联的扫描任务 ID。</summary>
    public Guid? ScanRunId { get; set; }
    /// <summary>Defender 威胁 ID（当来源为 Defender 时）。</summary>
    public long? DefenderThreatId { get; set; }
}

/// <summary>扫描类型。</summary>
public enum ScanType
{
    Quick,
    Full,
    Custom,
}

/// <summary>扫描状态机。</summary>
public enum ScanState
{
    Idle,
    Preparing,
    Running,
    Paused,
    Cancelling,
    Completed,
    Cancelled,
    Failed,
}

/// <summary>扫描进度快照（UI 绑定用）。</summary>
public class ScanProgress
{
    /// <summary>本次扫描的唯一标识。威胁记录、扫描记录都使用它，便于按扫描归档与交叉校验。</summary>
    public Guid RunId { get; set; }
    public ScanState State { get; set; } = ScanState.Idle;
    public ScanType Type { get; set; }
    public string CurrentItem { get; set; } = string.Empty;
    public long FilesTotal { get; set; }
    public long FilesScanned { get; set; }
    public int Percent => FilesTotal > 0 ? Math.Min(100, (int)(FilesScanned * 100 / FilesTotal)) : 0;
    public double FilesPerSecond { get; set; }
    public int ThreatsFound { get; set; }
    public TimeSpan Elapsed { get; set; }
    public string EngineName { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

/// <summary>一次扫描任务的汇总记录。</summary>
public class ScanRunRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public ScanType Type { get; set; }
    public DateTime StartedAt { get; set; }
    public DateTime? FinishedAt { get; set; }
    public ScanState FinalState { get; set; }
    public long FilesScanned { get; set; }
    public int ThreatsFound { get; set; }
    public string Engines { get; set; } = string.Empty;
    /// <summary>扫描范围描述（路径列表摘要）。</summary>
    public string Scope { get; set; } = string.Empty;
    /// <summary>未覆盖范围说明（如实披露，不夸大覆盖能力）。</summary>
    public string UncoveredNotes { get; set; } = string.Empty;
}
