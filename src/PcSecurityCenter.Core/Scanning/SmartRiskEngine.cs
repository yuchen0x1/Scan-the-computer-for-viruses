using System.Security.Cryptography;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;

namespace PcSecurityCenter.Core.Scanning;

/// <summary>
/// 智能风险引擎（第二引擎，规则可扩展）。
/// 原则：只有存在明确可解释证据时才报告，且结论级别为 Suspicious/Notice（可疑/提示），
/// 绝不把未知文件直接判定为病毒。病毒判定以 Defender 引擎结论为准。
/// </summary>
public class SmartRiskEngine : IScanEngine
{
    public string Name => "SmartRisk";
    public bool IsAvailable => true;

    /// <summary>可执行扩展集合（用于风险规则匹配）。</summary>
    private static readonly HashSet<string> ExecutableExt = new(StringComparer.OrdinalIgnoreCase)
    { ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".hta", ".msi", ".lnk" };

    /// <summary>脚本类扩展（做内容规则检查）。</summary>
    private static readonly HashSet<string> ScriptExt = new(StringComparer.OrdinalIgnoreCase)
    { ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".hta" };

    private static readonly string[] StartupDirs =
    [
        Environment.GetFolderPath(Environment.SpecialFolder.Startup),
        Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
    ];

    public async IAsyncEnumerable<ThreatInfo> ScanFilesAsync(
        IReadOnlyList<string> files, ScanContext context, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        // 节流策略：不在单文件层做延迟（会导致大范围扫描过慢），
        // 由编排器按批控制节奏；这里仅在文件间让出调度。
        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ThreatInfo? threat = null;
            try
            {
                threat = Inspect(file, context);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception) { /* 单文件检查失败不中断扫描 */ }
            if (threat != null) yield return threat;
        }
    }

    private ThreatInfo? Inspect(string file, ScanContext context)
    {
        var attr = FileEnumerator.SafeAttributes(file);
        if (attr == null) return null;
        var ext = Path.GetExtension(file);
        var dir = Path.GetDirectoryName(file) ?? string.Empty;
        var name = Path.GetFileName(file);
        var isStartupDir = StartupDirs.Any(s => !string.IsNullOrEmpty(s) &&
            dir.StartsWith(s, StringComparison.OrdinalIgnoreCase));

        // 规则 1：启动目录中的脚本文件 → 检查内容中的持久化/下载行为
        if (isStartupDir && ScriptExt.Contains(ext))
        {
            var evidence = ScriptContentIndicators(file);
            if (evidence.Count > 0)
            {
                return MakeThreat(file,
                    $"启动目录中的可疑脚本：{name}",
                    ThreatSeverity.High, DetectionKind.Suspicious,
                    "脚本内容包含以下可疑行为：" + string.Join("；", evidence),
                    "该脚本位于开机自启动目录且包含下载或隐藏执行行为。建议检查脚本内容，确认来源后隔离或删除。", context);
            }
            // 启动目录中的脚本本身值得提示（即使内容无明显恶意）
            return MakeThreat(file, $"启动目录中的脚本文件：{name}",
                ThreatSeverity.Medium, DetectionKind.Notice,
                "位于开机自启动目录的脚本文件",
                "若非本人添加，请检查脚本内容并考虑移除。", context);
        }

        // 规则 2：双扩展名伪装（如 invoice.pdf.exe）
        if (ExecutableExt.Contains(ext) && HasDoubleExtension(name))
        {
            return MakeThreat(file, $"双扩展名伪装文件：{name}",
                ThreatSeverity.Medium, DetectionKind.Suspicious,
                "文件名包含双扩展名，常见于恶意文件伪装",
                "此类文件常通过伪装文档图标诱导运行。确认来源后建议隔离。", context);
        }

        // 规则 3：下载/临时目录中的屏幕保护与脚本文件
        if ((IsUnderTempOrDownload(dir)) && (ext == ".scr" || ScriptExt.Contains(ext)))
        {
            return MakeThreat(file, $"临时/下载目录中的可执行脚本：{name}",
                ThreatSeverity.Medium, DetectionKind.Suspicious,
                $"位于 {dir} 的 {ext} 文件，屏幕保护/脚本常被用于传播",
                "请确认文件来源；非本人下载的此类文件建议隔离。", context);
        }

        // 规则 4：临时目录中隐藏属性的 PE
        if (ExecutableExt.Contains(ext) && attr.Value.HasFlag(FileAttributes.Hidden)
            && IsUnderTempOrDownload(dir))
        {
            return MakeThreat(file, $"临时目录中的隐藏可执行文件：{name}",
                ThreatSeverity.Medium, DetectionKind.Suspicious,
                "可执行文件带有隐藏属性且位于临时目录，符合恶意软件驻留特征",
                "确认来源后建议隔离。", context);
        }

        return null;
    }

    private static bool IsUnderTempOrDownload(string dir)
    {
        var temp = Path.GetTempPath();
        var up = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (dir.StartsWith(temp, StringComparison.OrdinalIgnoreCase)) return true;
        if (!string.IsNullOrEmpty(up) && dir.StartsWith(Path.Combine(up, "Downloads"), StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static bool HasDoubleExtension(string fileName)
    {
        var dot = fileName.LastIndexOf('.');
        if (dot <= 0) return false;
        var second = fileName.LastIndexOf('.', dot - 1);
        if (second < 0) return false;
        var inner = fileName.Substring(second + 1, dot - second - 1).ToLowerInvariant();
        return inner is "pdf" or "doc" or "docx" or "jpg" or "png" or "txt" or "xls" or "xlsx";
    }

    /// <summary>检查脚本内容中的可疑行为，返回命中证据列表。</summary>
    public static List<string> ScriptContentIndicators(string file)
    {
        var hits = new List<string>();
        try
        {
            // 只读文件前段（256K 字符上限），超大脚本同样检查，不做整体跳过
            string content;
            using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var sr = new StreamReader(fs, System.Text.Encoding.UTF8, true))
            {
                var buf = new char[256 * 1024];
                var n = sr.Read(buf, 0, buf.Length);
                content = new string(buf, 0, n);
            }
            static bool Has(string t, string k) => t.Contains(k, StringComparison.OrdinalIgnoreCase);
            if (Has(content, "-enc ") || Has(content, "-encodedcommand")) hits.Add("PowerShell 编码命令执行（-enc）");
            if (Has(content, "bypass") && Has(content, "powershell")) hits.Add("绕过执行策略调用 PowerShell");
            if (Has(content, "net.webclient") || Has(content, "invoke-webrequest") || Has(content, "downloadfile") ||
                Has(content, "curl ") || Has(content, "bitsadmin") || Has(content, "certutil -urlcache"))
                hits.Add("脚本包含文件下载行为");
            if (Has(content, "currentversion\\run") || Has(content, "currentversion\\runonce"))
                hits.Add("写注册表启动项实现持久化");
            if (Has(content, "wscript.sleep") && (Has(content, "sendkeys") || Has(content, "shell.run")))
                hits.Add("模拟按键/隐藏执行行为");
            if (Has(content, "schtasks /create") || Has(content, "register-scheduledtask"))
                hits.Add("创建计划任务实现持久化");
        }
        catch (Exception) { }
        return hits;
    }

    private static ThreatInfo MakeThreat(string file, string name, ThreatSeverity sev, DetectionKind kind,
        string evidence, string recommendation, ScanContext context)
    {
        string sha = string.Empty;
        try
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sha2 = SHA256.Create();
            sha = Convert.ToHexString(sha2.ComputeHash(fs));
        }
        catch (Exception) { }
        return new ThreatInfo
        {
            Name = name,
            Severity = sev,
            Kind = kind,
            FilePath = file,
            Engine = "SmartRisk",
            Evidence = evidence,
            Recommendation = recommendation,
            Sha256 = sha,
            ScanRunId = context.ScanRunId,
        };
    }
}
