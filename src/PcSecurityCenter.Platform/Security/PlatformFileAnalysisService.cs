using System.Security.Cryptography;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.FileAnalysis;
using PcSecurityCenter.Core.Models;

namespace PcSecurityCenter.Platform.Security;

/// <summary>文件分析服务（Platform 实现）：Core 分析器 + WinVerifyTrust 签名验证。</summary>
public class PlatformFileAnalysisService : IFileAnalysisService
{
    private readonly FileAnalyzer _analyzer;

    public PlatformFileAnalysisService()
    {
        _analyzer = new FileAnalyzer(async path =>
        {
            var v = SignatureVerifier.Verify(path);
            if (v.IsSigned)
            {
                var probe = await SignatureVerifier.ProbeAsync(path).ConfigureAwait(false);
                return (v.IsValid, probe.subject ?? v.Subject, v.StatusText);
            }
            return (false, v.Subject, v.StatusText);
        });
    }

    public Task<FileAnalysisReport> AnalyzeAsync(string filePath, CancellationToken ct = default)
        => _analyzer.AnalyzeAsync(filePath, ct);

    public async Task<string> ComputeSha256Async(string filePath, CancellationToken ct = default)
    {
        await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
            512 * 1024, FileOptions.Asynchronous);
        using var sha = SHA256.Create();
        return Convert.ToHexString(await sha.ComputeHashAsync(fs, ct));
    }
}
