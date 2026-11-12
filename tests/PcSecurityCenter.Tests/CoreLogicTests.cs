using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.FileAnalysis;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Core.Reporting;
using PcSecurityCenter.Core.Scanning;
using PcSecurityCenter.Core.SecurityChecks;
using PcSecurityCenter.Core.Utils;
using Xunit;

namespace PcSecurityCenter.Tests;

/// <summary>评分计算器：公开规则的量化验证。</summary>
public class ScoreCalculatorTests
{
    private readonly ScoreCalculator _calc = new();

    private static SecurityCheckItem Check(string id, CheckStatus status, int weight = 10, string category = "测试") => new()
    {
        Id = id, Name = id, Category = category, Status = status,
        Result = "x", Method = "test", Weight = weight,
    };

    [Fact]
    public void AllOk_ShouldScore100()
    {
        var checks = new[] { Check("a", CheckStatus.Ok), Check("b", CheckStatus.Ok, 5) };
        var score = _calc.FromChecks(checks);
        Assert.Equal(100, score.Total);
        Assert.Equal("优秀", score.Grade);
    }

    [Fact]
    public void AllRisk_ShouldScore0()
    {
        var checks = new[] { Check("a", CheckStatus.Risk), Check("b", CheckStatus.Risk, 5) };
        var score = _calc.FromChecks(checks);
        Assert.Equal(0, score.Total);
        Assert.Equal("危险", score.Grade);
    }

    [Fact]
    public void Warning_CountsAs60Percent()
    {
        var checks = new[] { Check("a", CheckStatus.Warning) };
        var score = _calc.FromChecks(checks);
        Assert.Equal(60, score.Total);
    }

    [Fact]
    public void NotSupported_ShouldNotCountInDenominator()
    {
        // 10分 Ok + 10分 NotSupported：分母只算 10 分 → 100 分（不因"读不到"而扣分）
        var checks = new[] { Check("a", CheckStatus.Ok), Check("b", CheckStatus.NotSupported) };
        var score = _calc.FromChecks(checks);
        Assert.Equal(100, score.Total);
    }

    [Fact]
    public void NoPermission_ShouldNotCountInDenominator()
    {
        var checks = new[] { Check("a", CheckStatus.Ok), Check("b", CheckStatus.NoPermission) };
        Assert.Equal(100, _calc.FromChecks(checks).Total);
    }

    [Fact]
    public void EmptyChecks_ShouldBeUnknown()
    {
        var score = _calc.FromChecks(Array.Empty<SecurityCheckItem>());
        Assert.Equal(0, score.Total);
        Assert.Equal("未知", score.Grade);
    }

    [Fact]
    public void CategoryScores_AreIndependent()
    {
        var checks = new[]
        {
            Check("a", CheckStatus.Ok, 10, "防护能力"),
            Check("b", CheckStatus.Risk, 10, "网络安全"),
        };
        var score = _calc.FromChecks(checks);
        Assert.Equal(100, score.CategoryScores["防护能力"]);
        Assert.Equal(0, score.CategoryScores["网络安全"]);
        Assert.Equal(50, score.Total);
    }
}

/// <summary>扫描范围构建：范围必须真实可解释。</summary>
public class ScanRangeBuilderTests
{
    [Fact]
    public void QuickRange_ContainsStartupAndTempAndDownloads()
    {
        var builder = new ScanRangeBuilder();
        var range = builder.BuildQuickRange();
        Assert.Contains(Path.GetTempPath().TrimEnd('\\'), range.Select(r => r.TrimEnd('\\')),
            StringComparer.OrdinalIgnoreCase);
        var startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (!string.IsNullOrEmpty(startup))
            Assert.Contains(range, r => r.Equals(startup, StringComparison.OrdinalIgnoreCase));
        // 下载目录
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        Assert.Contains(range, r => r.Equals(downloads, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void FullRange_OnlyFixedDrives()
    {
        var builder = new ScanRangeBuilder();
        var range = builder.BuildFullRange();
        Assert.NotEmpty(range);
        foreach (var r in range)
        {
            var info = new DriveInfo(r);
            Assert.Equal(DriveType.Fixed, info.DriveType);
        }
    }

    [Fact]
    public void FullRange_WithExplicitDrives_RespectsFilter()
    {
        var builder = new ScanRangeBuilder();
        var range = builder.BuildFullRange(new[] { @"C:\", @"Q:\不存在\" });
        Assert.Single(range);
        Assert.Equal(@"C:\", range[0]);
    }
}

/// <summary>路径安全：防路径遍历与关键路径保护。</summary>
public class PathSafetyTests
{
    [Fact]
    public void NormalizeInside_RejectsTraversal()
    {
        var result = PathSafety.NormalizeInside(@"C:\temp\base", @"..\..\Windows\System32\evil.dll");
        Assert.Null(result);
    }

    [Fact]
    public void NormalizeInside_AcceptsNormal()
    {
        var result = PathSafety.NormalizeInside(@"C:\temp\base", "sub\\file.txt");
        Assert.NotNull(result);
        Assert.StartsWith(@"C:\temp\base", result!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IsCriticalSystemPath_FlagsWindows()
    {
        Assert.True(PathSafety.IsCriticalSystemPath(@"C:\Windows"));
        Assert.True(PathSafety.IsCriticalSystemPath(@"C:\Program Files"));
        Assert.False(PathSafety.IsCriticalSystemPath(@"C:\Users\test\AppData\Local\Temp"));
    }

    [Fact]
    public void IsSafeToDelete_RejectsInvalidOrCurrentProcess()
    {
        Assert.False(PathSafety.IsSafeToDelete(@"Q:\不存在\file.txt"));
        Assert.False(PathSafety.IsSafeToDelete(@"..\relative\path"));
        if (Environment.ProcessPath != null)
            Assert.False(PathSafety.IsSafeToDelete(Environment.ProcessPath));
    }
}

/// <summary>熵计算：已知值验证。</summary>
public class EntropyCalculatorTests
{
    [Fact]
    public void UniformBytes_HaveZeroEntropy()
    {
        Assert.Equal(0, EntropyCalculator.Compute(new byte[1024]));
    }

    [Fact]
    public void UniformRandom_HasHighEntropy()
    {
        var data = new byte[65536];
        var rng = Random.Shared;
        for (var i = 0; i < data.Length; i++) data[i] = (byte)rng.Next(256);
        var e = EntropyCalculator.Compute(data);
        Assert.True(e > 7.9, $"期望 >7.9，实际 {e:F3}");
    }

    [Fact]
    public void HalfZeroHalfOne_HasOneBitEntropy()
    {
        var data = new byte[1024];
        Array.Fill(data, (byte)0, 0, 512);
        Array.Fill(data, (byte)1, 512, 512);
        Assert.Equal(1.0, EntropyCalculator.Compute(data), 2);
    }
}

/// <summary>PE 解析：真实系统文件 + 非 PE 文件。</summary>
public class PeParserTests
{
    [Fact]
    public void Parse_RealSystemPe_ShouldSucceed()
    {
        // 注意：Win11 的 notepad.exe 是数百字节的 PE 存根，不适合做完整解析测试；用 cmd.exe
        var pe = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        Assert.True(File.Exists(pe), "cmd.exe 不存在");
        var info = PeParser.Parse(pe);
        Assert.True(info.IsPe);
        Assert.True(info.SectionCount > 0);
        Assert.NotEmpty(info.SectionNames);
        Assert.Contains(".text", info.SectionNames);
        Assert.False(string.IsNullOrEmpty(info.Machine));
    }

    [Fact]
    public void Parse_TextFile_ShouldFail()
    {
        var temp = Path.Combine(Path.GetTempPath(), $"psc_test_{Guid.NewGuid():N}.txt");
        File.WriteAllText(temp, "hello, not a pe file");
        try
        {
            var info = PeParser.Parse(temp);
            Assert.False(info.IsPe);
            Assert.False(string.IsNullOrEmpty(info.Error));
        }
        finally { File.Delete(temp); }
    }

    [Fact]
    public void Parse_TooSmallFile_ShouldFail()
    {
        var temp = Path.Combine(Path.GetTempPath(), $"psc_test_{Guid.NewGuid():N}.bin");
        File.WriteAllBytes(temp, new byte[] { 0x4D, 0x5A });
        try
        {
            var info = PeParser.Parse(temp);
            Assert.False(info.IsPe);
        }
        finally { File.Delete(temp); }
    }
}

/// <summary>智能风险引擎：规则命中与不误报。</summary>
public class SmartRiskEngineTests
{
    [Fact]
    public void ScriptContentIndicators_DetectsEncodedPowerShell()
    {
        var temp = Path.Combine(Path.GetTempPath(), $"psc_test_{Guid.NewGuid():N}.ps1");
        File.WriteAllText(temp, "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkA");
        try
        {
            var hits = SmartRiskEngine.ScriptContentIndicators(temp);
            Assert.Contains(hits, h => h.Contains("编码命令"));
        }
        finally { File.Delete(temp); }
    }

    [Fact]
    public void ScriptContentIndicators_CleanScript_NoHits()
    {
        var temp = Path.Combine(Path.GetTempPath(), $"psc_test_{Guid.NewGuid():N}.ps1");
        File.WriteAllText(temp, "Write-Host 'hello world'");
        try
        {
            var hits = SmartRiskEngine.ScriptContentIndicators(temp);
            Assert.Empty(hits);
        }
        finally { File.Delete(temp); }
    }

    [Fact]
    public async Task Engine_FlagsDoubleExtensionFile()
    {
        // 构造: 临时目录中的 "invoice.pdf.exe"（无害内容）
        var temp = Path.Combine(Path.GetTempPath(), "psc_e2e_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(temp);
        var fake = Path.Combine(temp, "invoice.pdf.exe");
        await File.WriteAllBytesAsync(fake, new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x01, 0x02 });
        try
        {
            var engine = new SmartRiskEngine();
            var ctx = new ScanContext { Type = ScanType.Quick, ScanRunId = Guid.NewGuid(), RootPaths = new[] { temp } };
            var found = new List<ThreatInfo>();
            await foreach (var t in engine.ScanFilesAsync(new[] { fake }, ctx, CancellationToken.None))
                found.Add(t);
            Assert.Contains(found, t => t.Name.Contains("双扩展名") && t.Kind == DetectionKind.Suspicious);
            // SmartRisk 绝不给出"确认病毒"结论
            Assert.DoesNotContain(found, t => t.Kind == DetectionKind.Confirmed);
        }
        finally { Directory.Delete(temp, true); }
    }

    [Fact]
    public async Task Engine_IgnoresNormalTextFile()
    {
        var temp = Path.Combine(Path.GetTempPath(), $"psc_test_{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(temp, "normal content");
        try
        {
            var engine = new SmartRiskEngine();
            var ctx = new ScanContext { Type = ScanType.Quick, ScanRunId = Guid.NewGuid() };
            var found = new List<ThreatInfo>();
            await foreach (var t in engine.ScanFilesAsync(new[] { temp }, ctx, CancellationToken.None))
                found.Add(t);
            Assert.Empty(found);
        }
        finally { File.Delete(temp); }
    }

    [Fact]
    public async Task Engine_ExclusionPath_SuppressesSmartRiskResult()
    {
        var temp = Path.Combine(Path.GetTempPath(), "psc_exclusion_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        var fake = Path.Combine(temp, "invoice.pdf.exe");
        await File.WriteAllBytesAsync(fake, new byte[] { 0x4D, 0x5A, 0x90, 0x00 });
        try
        {
            var engine = new SmartRiskEngine();
            var ctx = new ScanContext
            {
                Type = ScanType.Quick,
                ScanRunId = Guid.NewGuid(),
                RootPaths = new[] { temp },
                ExcludedPaths = new[] { temp },
            };
            var found = new List<ThreatInfo>();
            await foreach (var t in engine.ScanFilesAsync(new[] { fake }, ctx, CancellationToken.None)) found.Add(t);
            Assert.Empty(found);
        }
        finally { Directory.Delete(temp, true); }
    }

    [Fact]
    public async Task Engine_CleanPowerShellInTemp_IsLowNotice()
    {
        var temp = Path.Combine(Path.GetTempPath(), "psc_low_signal_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        var script = Path.Combine(temp, "build.cmd");
        await File.WriteAllTextAsync(script, "echo build");
        try
        {
            var engine = new SmartRiskEngine();
            var found = new List<ThreatInfo>();
            await foreach (var t in engine.ScanFilesAsync(new[] { script }, new ScanContext { Type = ScanType.Quick }, CancellationToken.None)) found.Add(t);
            var result = Assert.Single(found);
            Assert.Equal(ThreatSeverity.Low, result.Severity);
            Assert.Equal(DetectionKind.Notice, result.Kind);
        }
        finally { Directory.Delete(temp, true); }
    }
}

/// <summary>HTML 报告构建。</summary>
public class HtmlReportBuilderTests
{
    [Fact]
    public void Build_ContainsAllSections_AndEscapes()
    {
        var data = new ReportData
        {
            MachineName = "TEST<PC>",
            OsName = "Windows 11",
            Score = new SecurityScore { Total = 88, Grade = "良好", Summary = "测试" },
            Checks = new List<SecurityCheckItem>
            {
                new() { Id = "x", Name = "检查项 <A>", Category = "防护能力", Status = CheckStatus.Ok, Result = "正常", Method = "测试" },
            },
            Scans = new List<ScanRunRecord>
            {
                new() { Type = ScanType.Quick, StartedAt = DateTime.Now, FinalState = ScanState.Completed, FilesScanned = 100, ThreatsFound = 1, Engines = "Defender" },
            },
            Threats = new List<ThreatInfo> { new() { Name = "威胁", FilePath = @"C:\evil.exe", Engine = "Defender", Evidence = "test" } },
        };
        var html = HtmlReportBuilder.Build(data);
        Assert.Contains("综合安全评分", html);
        Assert.Contains("系统安全检查明细", html);
        Assert.Contains("扫描记录", html);
        Assert.Contains("威胁与风险", html);
        Assert.Contains("覆盖范围与限制", html);
        // 转义验证：主机名与检查名中的尖括号必须转义
        Assert.Contains("TEST&lt;PC&gt;", html);
        Assert.Contains("检查项 &lt;A&gt;", html);
        Assert.DoesNotContain("TEST<PC>", html);
    }
}

/// <summary>评分边界与风险引擎大小写（v1.1.0 加固回归）。</summary>
public class ScoreAndRiskEdgeTests
{
    private static SecurityCheckItem Item(string id, CheckStatus status, int weight, string cat = "X") => new()
    {
        Id = id, Name = id, Category = cat, Status = status, Result = "", Method = "test", Weight = weight,
    };

    [Fact]
    public void FromChecks_全部不可读_标注未知而非危险()
    {
        var calc = new ScoreCalculator();
        var s = calc.FromChecks(new[]
        {
            Item("a", CheckStatus.NoPermission, 5),
            Item("b", CheckStatus.NotSupported, 3),
            Item("c", CheckStatus.Error, 2),
        });
        Assert.Equal("未知", s.Grade);
    }

    [Fact]
    public void FromChecks_不可读项不计入分母()
    {
        var calc = new ScoreCalculator();
        var s = calc.FromChecks(new[]
        {
            Item("ok", CheckStatus.Ok, 3),
            Item("no", CheckStatus.NoPermission, 100),
        });
        Assert.Equal(100, s.Total);
    }

    [Theory]
    [InlineData("invoice.pdf.exe")]
    [InlineData("invoice.PDF.exe")]
    [InlineData("INVOICE.PdF.ExE")]
    public async Task Engine_双扩展名_大小写不敏感(string fileName)
    {
        var temp = Path.Combine(Path.GetTempPath(), "psc_case_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(temp);
        var fake = Path.Combine(temp, fileName);
        await File.WriteAllBytesAsync(fake, new byte[] { 0x4D, 0x5A, 0x90, 0x00 });
        try
        {
            var engine = new SmartRiskEngine();
            var ctx = new ScanContext { Type = ScanType.Quick, ScanRunId = Guid.NewGuid(), RootPaths = new[] { temp } };
            var found = new List<ThreatInfo>();
            await foreach (var t in engine.ScanFilesAsync(new[] { fake }, ctx, CancellationToken.None))
                found.Add(t);
            Assert.Contains(found, t => t.Name.Contains("双扩展名"));
        }
        finally { Directory.Delete(temp, true); }
    }
}
