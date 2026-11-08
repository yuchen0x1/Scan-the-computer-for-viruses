namespace PcSecurityCenter.Core.Models;

/// <summary>安全检查项结论状态。无法读取时必须是 NotSupported / NoPermission，绝不能默认视为安全。</summary>
public enum CheckStatus
{
    /// <summary>检查通过。</summary>
    Ok,
    /// <summary>存在可改进项。</summary>
    Warning,
    /// <summary>存在风险。</summary>
    Risk,
    /// <summary>检查失败（接口异常）。</summary>
    Error,
    /// <summary>本机或当前环境不支持该项。</summary>
    NotSupported,
    /// <summary>权限不足，无法读取。</summary>
    NoPermission,
}

/// <summary>检查项类别。</summary>
public static class CheckCategories
{
    public const string Protection = "防护能力";
    public const string Update = "系统更新";
    public const string Policy = "安全策略";
    public const string Account = "账户安全";
    public const string Encryption = "加密与固件";
    public const string Network = "网络安全";
}

/// <summary>单项安全检查结果。</summary>
public class SecurityCheckItem
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string Category { get; init; }
    public CheckStatus Status { get; set; }
    /// <summary>检查结果的人类可读摘要。</summary>
    public required string Result { get; set; }
    /// <summary>检测方式（调用了什么接口/命令）。</summary>
    public required string Method { get; init; }
    /// <summary>风险说明。</summary>
    public string RiskExplanation { get; set; } = string.Empty;
    /// <summary>推荐处理方案。</summary>
    public string Recommendation { get; set; } = string.Empty;
    /// <summary>该检查项在评分中的权重。</summary>
    public int Weight { get; init; } = 5;
    public DateTime CheckedAt { get; init; } = DateTime.Now;
}

/// <summary>综合安全评分结果。评分完全由真实检查项推导，规则公开。</summary>
public class SecurityScore
{
    public int Total { get; set; }
    public string Grade { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public Dictionary<string, int> CategoryScores { get; set; } = new();
}

/// <summary>安全事件（实时防护、威胁处理、系统修改记录等）。</summary>
public enum SecurityEventType
{
    RealtimeDetection,
    ThreatAction,
    SystemCheck,
    Maintenance,
    SystemModification,
    NetworkAlert,
    StartupChange,
    Info,
}

public class SecurityEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public SecurityEventType Type { get; set; }
    public ThreatSeverity Severity { get; set; } = ThreatSeverity.Info;
    public required string Title { get; set; }
    public string Detail { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.Now;
}

/// <summary>全局防护状态胶囊。</summary>
public enum GlobalSafetyState
{
    Good,
    Attention,
    AtRisk,
    Unknown,
}
