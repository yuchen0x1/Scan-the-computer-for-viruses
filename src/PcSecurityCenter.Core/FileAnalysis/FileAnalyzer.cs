using System.Security.Cryptography;
using PcSecurityCenter.Core.Models;

namespace PcSecurityCenter.Core.FileAnalysis;

/// <summary>
/// 文件分析器（Core 部分）：哈希、熵、PE 信息与启发式指标。
/// 数字签名验证由 Platform 层通过 WinVerifyTrust 提供（通过回调注入）。
/// </summary>
public class FileAnalyzer
{
    private readonly Func<string, Task<(bool? signed, string? subject, string? status)>>? _signatureProbe;

    public FileAnalyzer(Func<string, Task<(bool? signed, string? subject, string? status)>>? signatureProbe = null)
    {
        _signatureProbe = signatureProbe;
    }

    public async Task<FileAnalysisReport> AnalyzeAsync(string filePath, CancellationToken ct = default)
    {
        var report = new FileAnalysisReport { FilePath = filePath };
        var full = System.IO.Path.GetFullPath(filePath);
        if (!File.Exists(full)) throw new FileNotFoundException("文件不存在", full);
        report.FilePath = full;

        var fi = new FileInfo(full);
        report.SizeBytes = fi.Length;
        report.CreatedAt = fi.CreationTime;
        report.ModifiedAt = fi.LastWriteTime;
        report.FileTypeName = GuessTypeName(full, fi.Length);

        // 哈希（流式，支持取消）
        report.Sha256 = await ComputeHashAsync(full, SHA256.Create(), ct);
        report.Sha1 = await ComputeHashAsync(full, SHA1.Create(), ct);
        report.Md5 = await ComputeHashAsync(full, MD5.Create(), ct);

        // 熵
        report.EntropyBitsPerByte = await EntropyCalculator.ComputeSampledAsync(full, ct);

        // PE 信息
        var pe = await Task.Run(() => PeParser.Parse(full), ct);
        report.IsPe = pe.IsPe;
        if (pe.IsPe)
        {
            report.PeMachine = pe.Is64Bit ? $"{pe.Machine} (64 位)" : pe.Machine;
            (bool? signed, string? subject, string? status)? sig =
                _signatureProbe is null ? null : await _signatureProbe(full).ConfigureAwait(false);
            report.PeIsSigned = sig?.signed;
            report.SignatureSubject = sig?.subject;
            report.SignatureStatus = sig?.status;
        }

        // 风险指标（只提示，不下定论）
        var indicators = new List<string>();
        var name = System.IO.Path.GetFileName(full);
        if (pe.IsPe && pe.IsDotNet) indicators.Add(".NET 程序集");
        if (pe.IsPe && pe.HasDigitalSignatureDirectory == false) indicators.Add("PE 不包含数字签名目录");
        if (pe.IsPe && report.PeIsSigned == false) indicators.Add("数字签名验证未通过或缺失");
        if (report.EntropyBitsPerByte > 7.2 && pe.IsPe) indicators.Add($"PE 内容熵值偏高（{report.EntropyBitsPerByte:F2} bits/byte），可能加壳或加密（仅提示）");
        if (name.Contains(".pdf.", StringComparison.OrdinalIgnoreCase) || name.Contains(".doc.", StringComparison.OrdinalIgnoreCase))
            indicators.Add("文件名疑似伪装（双扩展名）");
        var attr = fi.Attributes;
        if (attr.HasFlag(FileAttributes.Hidden) && pe.IsPe) indicators.Add("可执行文件带隐藏属性");

        report.Indicators = indicators;
        report.RiskLevel = indicators.Count(i => i.Contains("签名") || i.Contains("熵") || i.Contains("隐藏")) switch
        {
            0 => ThreatSeverity.Info,
            1 => ThreatSeverity.Low,
            2 => ThreatSeverity.Medium,
            _ => ThreatSeverity.High,
        };
        report.RiskSummary = report.RiskLevel switch
        {
            ThreatSeverity.Info => "未发现可疑指标。注意：本分析不等于病毒判定，如需确认请提交引擎扫描。",
            ThreatSeverity.Low => "存在少量可关注指标，请结合文件来源判断。",
            ThreatSeverity.Medium => "存在多项可疑指标，建议使用病毒扫描确认。",
            _ => "存在较多可疑指标，强烈建议隔离并提交完整病毒扫描。",
        };
        return report;
    }

    public static async Task<string> ComputeHashAsync(string filePath, HashAlgorithm algo, CancellationToken ct = default)
    {
        await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
            bufferSize: 1024 * 512, FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(await algo.ComputeHashAsync(fs, ct));
    }

    public static string ComputeHash(string filePath, HashAlgorithm algo)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 512 * 1024);
        return Convert.ToHexString(algo.ComputeHash(fs));
    }

    private static string GuessTypeName(string path, long size)
    {
        var ext = System.IO.Path.GetExtension(path).ToLowerInvariant();
        return ext switch
        {
            ".exe" or ".dll" or ".sys" or ".scr" => "Windows 可执行文件/库",
            ".msi" => "Windows 安装包",
            ".ps1" => "PowerShell 脚本",
            ".bat" or ".cmd" => "批处理脚本",
            ".vbs" or ".vbe" or ".js" or ".jse" => "脚本文件",
            ".pdf" => "PDF 文档",
            ".doc" or ".docx" => "Word 文档",
            ".zip" => "ZIP 压缩包",
            ".7z" => "7z 压缩包",
            "" => size > 0 ? "无扩展名文件" : "空文件",
            _ => $"{ext.TrimStart('.').ToUpperInvariant()} 文件",
        };
    }
}
