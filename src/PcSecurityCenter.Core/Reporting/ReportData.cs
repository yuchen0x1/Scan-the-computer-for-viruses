using System.Text;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Core.Utils;

namespace PcSecurityCenter.Core.Reporting;

/// <summary>报告中心数据（由 Data 层聚合后传入）。</summary>
public class ReportData
{
    public DateTime GeneratedAt { get; set; } = DateTime.Now;
    public string MachineName { get; set; } = string.Empty;
    public string OsName { get; set; } = string.Empty;
    public SecurityScore? Score { get; set; }
    public List<ScanRunRecord> Scans { get; set; } = new();
    public List<SecurityCheckItem> Checks { get; set; } = new();
    public List<ThreatInfo> Threats { get; set; } = new();
    public List<SecurityEvent> Events { get; set; } = new();
    public List<MaintenanceRunRecord> MaintenanceRuns { get; set; } = new();
}

/// <summary>系统维护执行记录。</summary>
public class MaintenanceRunRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTime StartedAt { get; set; }
    public DateTime? FinishedAt { get; set; }
    public string Action { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
    public long FreedBytes { get; set; }
    public bool Success { get; set; }
    public string FreedBytesHuman => PcSecurityCenter.Core.Utils.SizeFormat.Format(FreedBytes);
    public string SuccessText => Success ? "成功" : "失败";
}

/// <summary>HTML 报告构建器（自包含单文件，可直接在浏览器打开）。</summary>
public static class HtmlReportBuilder
{
    public static string Build(ReportData data)
    {
        var sb = new StringBuilder(256 * 1024);
        sb.Append("""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>Windows 智能安全卫士 - 安全报告</title>""");
        sb.Append("""
<style>
:root{--bg:#0b1020;--card:#141a30;--line:#243055;--fg:#dfe7ff;--muted:#8ea0c9;--cyan:#22d3ee;--blue:#3b82f6;--ok:#34d399;--warn:#fbbf24;--bad:#f87171}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(160deg,#0b1020,#0e1530 60%,#0b1020);color:var(--fg);font:14px/1.7 "Microsoft YaHei UI","Segoe UI",sans-serif;padding:32px}
.wrap{max-width:1080px;margin:0 auto}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 12px;border-left:3px solid var(--cyan);padding-left:10px}
.sub{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin:10px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.kpi b{font-size:24px;display:block}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px}
.ok{background:rgba(52,211,153,.15);color:var(--ok)}
.warn{background:rgba(251,191,36,.15);color:var(--warn)}
.bad{background:rgba(248,113,113,.15);color:var(--bad)}
.mut{background:rgba(139,160,201,.15);color:var(--muted)}
footer{margin-top:34px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px}
code{background:#0d1330;padding:1px 6px;border-radius:6px;font-size:12px}
</style></head><body><div class="wrap">
""");
        sb.Append($"""
<h1>Windows 智能安全卫士 · 安全报告</h1>
<div class="sub">生成时间：{data.GeneratedAt:yyyy-MM-dd HH:mm:ss}　主机：{Escape(data.MachineName)}　系统：{Escape(data.OsName)}</div>
""");

        // 评分
        if (data.Score != null)
        {
            var grade = data.Score.Grade switch { "优秀" or "良好" => "ok", "一般" => "warn", _ => "bad" };
            sb.Append($"""
<h2>综合安全评分</h2><div class="grid">
<div class="kpi"><b>{data.Score.Total}</b>评分等级 <span class="pill {grade}">{Escape(data.Score.Grade)}</span></div>
<div class="kpi"><b>{Escape(data.Score.Summary)}</b>评分说明</div>
""");
            foreach (var (cat, val) in data.Score.CategoryScores)
                sb.Append($"""<div class="kpi"><b>{val}</b>{Escape(cat)}</div>""");
            sb.Append("</div>");
        }

        // 检查明细
        sb.Append("<h2>系统安全检查明细</h2><div class=\"card\"><table><tr><th>项目</th><th>类别</th><th>结果</th><th>状态</th><th>检测方式</th><th>建议</th></tr>");
        foreach (var c in data.Checks)
        {
            var (pill, label) = c.Status switch
            {
                CheckStatus.Ok => ("ok", "通过"),
                CheckStatus.Warning => ("warn", "注意"),
                CheckStatus.Risk => ("bad", "风险"),
                CheckStatus.Error => ("warn", "检查失败"),
                CheckStatus.NotSupported => ("mut", "暂不支持"),
                CheckStatus.NoPermission => ("mut", "权限不足"),
                _ => ("mut", "未知"),
            };
            sb.Append($"""<tr><td>{Escape(c.Name)}</td><td>{Escape(c.Category)}</td><td>{Escape(c.Result)}</td><td><span class="pill {pill}">{label}</span></td><td><code>{Escape(c.Method)}</code></td><td>{Escape(c.Recommendation)}</td></tr>""");
        }
        sb.Append("</table></div>");

        // 扫描记录
        sb.Append("<h2>扫描记录</h2><div class=\"card\"><table><tr><th>时间</th><th>类型</th><th>范围</th><th>文件数</th><th>风险数</th><th>引擎</th><th>结果</th></tr>");
        foreach (var s in data.Scans)
        {
            sb.Append($"""<tr><td>{s.StartedAt:yyyy-MM-dd HH:mm}</td><td>{ScanTypeName(s.Type)}</td><td>{Escape(Trunc(s.Scope, 80))}</td><td>{s.FilesScanned}</td><td>{s.ThreatsFound}</td><td>{Escape(s.Engines)}</td><td>{Escape(s.FinalState.ToString())}</td></tr>""");
        }
        if (data.Scans.Count == 0) sb.Append("<tr><td colspan=\"7\" class=\"sub\">暂无扫描记录</td></tr>");
        sb.Append("</table></div>");

        // 威胁
        sb.Append("<h2>威胁与风险</h2><div class=\"card\"><table><tr><th>名称</th><th>级别</th><th>路径</th><th>引擎</th><th>依据</th><th>状态</th></tr>");
        foreach (var t in data.Threats)
        {
            var pill = t.Severity switch
            {
                ThreatSeverity.Critical or ThreatSeverity.High => "bad",
                ThreatSeverity.Medium => "warn",
                _ => "mut",
            };
            sb.Append($"""<tr><td>{Escape(t.Name)}</td><td><span class="pill {pill}">{t.Severity}</span></td><td><code>{Escape(Trunc(t.FilePath, 90))}</code></td><td>{Escape(t.Engine)}</td><td>{Escape(t.Evidence)}</td><td>{t.Status}</td></tr>""");
        }
        if (data.Threats.Count == 0) sb.Append("<tr><td colspan=\"6\" class=\"sub\">暂无威胁记录</td></tr>");
        sb.Append("</table></div>");

        // 维护记录
        sb.Append("<h2>系统维护记录</h2><div class=\"card\"><table><tr><th>时间</th><th>操作</th><th>结果</th><th>释放空间</th></tr>");
        foreach (var m in data.MaintenanceRuns)
            sb.Append($"""<tr><td>{m.StartedAt:yyyy-MM-dd HH:mm}</td><td>{Escape(m.Action)}</td><td>{(m.Success ? "成功" : "失败")}</td><td>{SizeFormat.Format(m.FreedBytes)}</td></tr>""");
        if (data.MaintenanceRuns.Count == 0) sb.Append("<tr><td colspan=\"4\" class=\"sub\">暂无维护记录</td></tr>");
        sb.Append("</table></div>");

        // 事件
        sb.Append("<h2>最近安全事件</h2><div class=\"card\"><table><tr><th>时间</th><th>级别</th><th>事件</th></tr>");
        foreach (var e in data.Events.Take(100))
            sb.Append($"""<tr><td>{e.CreatedAt:MM-dd HH:mm:ss}</td><td>{e.Severity}</td><td>{Escape(e.Title)} — {Escape(e.Detail)}</td></tr>""");
        if (data.Events.Count == 0) sb.Append("<tr><td colspan=\"3\" class=\"sub\">暂无事件</td></tr>");
        sb.Append("</table></div>");

        sb.Append($"""
<footer>
<b>覆盖范围与限制（如实说明）：</b>本报告仅包含本工具实际执行的检查与扫描结果。病毒检测能力取决于 Microsoft Defender 病毒库与引擎，无法保证检测出所有威胁；
未授权执行的在线行为分析、内核级检测不在本工具能力范围内。评分反映的是本工具所定义检查项的量化结果，不代表系统绝对安全。<br>
数据来源：本机 Microsoft Defender 官方接口（PowerShell/MpCmdRun/WMI）、Windows 系统 API 与注册表只读查询。报告不包含任何上传行为。
</footer></div></body></html>
""");
        return sb.ToString();
    }

    private static string ScanTypeName(ScanType t) => t switch
    {
        ScanType.Quick => "快速扫描",
        ScanType.Full => "全盘扫描",
        _ => "自定义扫描",
    };

    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..n] + "…";

    private static string Escape(string? s)
    {
        if (string.IsNullOrEmpty(s)) return string.Empty;
        return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
    }
}
