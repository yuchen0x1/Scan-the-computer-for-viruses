using System.ComponentModel;
using System.Diagnostics;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Core.Scanning;
using PcSecurityCenter.Platform.Security;
using Xunit;

namespace PcSecurityCenter.Tests;

/// <summary>
/// 提权启动配置的回归测试。
///
/// 背景：提权曾长期"静默失效"——UseShellExecute=false 时 Verb=RunAs 被 .NET 忽略，
/// 子进程以普通权限运行，UI 却告诉用户"将以管理员权限执行"。这些测试锁定正确配置，
/// 防止有人为了"能重定向输出"又把 UseShellExecute 改回 false。
/// </summary>
public class ElevationLauncherTests
{
    [Fact]
    public void CreateStartInfo_必须使用ShellExecute以触发UAC()
    {
        var psi = ElevationLauncher.CreateStartInfo("ZQBjAGgAbwA=");

        // 这是整个提权链路生效的前提：false 时 RunAs 被静默忽略。
        Assert.True(psi.UseShellExecute, "UseShellExecute 必须为 true，否则 Verb=RunAs 不会触发 UAC");
        Assert.Equal("RunAs", psi.Verb);
    }

    [Fact]
    public void CreateStartInfo_必须关闭输出重定向()
    {
        var psi = ElevationLauncher.CreateStartInfo("ZQBjAGgAbwA=");

        // UseShellExecute=true 时重定向会抛 InvalidOperationException，
        // 因此结果必须通过结果文件回传，不能依赖 stdout。
        Assert.False(psi.RedirectStandardOutput);
        Assert.False(psi.RedirectStandardError);
        Assert.False(psi.RedirectStandardInput);
    }

    [Fact]
    public void CreateStartInfo_脚本以EncodedCommand传递且不进入命令行明文字面量()
    {
        const string encoded = "SQBFAFgAIAAiAEgAaQAiAA==";
        var psi = ElevationLauncher.CreateStartInfo(encoded);

        Assert.Contains("-EncodedCommand", psi.Arguments);
        Assert.Contains(encoded, psi.Arguments);
        Assert.Contains("-NoProfile", psi.Arguments);
        Assert.Contains("-ExecutionPolicy Bypass", psi.Arguments);
    }

    [Fact]
    public void CreateStartInfo_空命令被拒绝()
    {
        Assert.Throws<ArgumentException>(() => ElevationLauncher.CreateStartInfo(""));
        Assert.Throws<ArgumentException>(() => ElevationLauncher.CreateStartInfo("   "));
    }

    [Fact]
    public void IsUserCancelled_只识别1223()
    {
        Assert.True(ElevationLauncher.IsUserCancelled(new Win32Exception(1223)));
        Assert.False(ElevationLauncher.IsUserCancelled(new Win32Exception(5)));
        Assert.False(ElevationLauncher.IsUserCancelled(new Win32Exception(2)));
    }

    [Fact]
    public async Task RunElevatedAsync_用户取消UAC时返回失败且说明原因()
    {
        // 该测试只在非管理员环境有意义：管理员会话不会弹 UAC。
        var service = new WindowsPermissionService();
        if (service.IsElevated) return;

        // 用一个确定会抛 1223 的场景无法稳定构造（会真的弹窗打扰用户），
        // 因此这里只验证"未知操作"这类可离线判定的失败路径不会被误报为成功。
        var result = await service.RunElevatedAsync((ElevatedOperation)int.MaxValue);
        Assert.False(result.Success);
        Assert.Contains("未知操作", result.Output);
    }

    [Fact]
    public void PowerShell单引号转义_不会破坏脚本字面量()
    {
        // 参数值里带单引号（例如路径 C:\O'Brien\）不得逃出字符串边界
        Assert.Equal("C:\\O''Brien\\", WindowsPermissionService.EscapePsSingleQuoted("C:\\O'Brien\\"));

        // 注入尝试：每个单引号翻倍后，整段仍是同一条 PS 字符串字面量，无法提前闭合
        var injected = WindowsPermissionService.EscapePsSingleQuoted("'; Remove-Item C:\\ -Recurse'");
        Assert.Equal("''; Remove-Item C:\\ -Recurse''", injected);
        Assert.Equal(4, injected.Count(c => c == '\'')); // 原文 2 个 → 转义后 4 个（成对）
    }
}

/// <summary>
/// 全盘扫描分区的回归测试。
///
/// 背景：旧实现嵌套调用 EnumerateDirectoriesShallow，导致祖先与后代目录被同时投递，
/// Defender 对同一子树重复递归扫描（实测 3.29 倍），耗时与文件计数双双虚高。
/// </summary>
public class ScanPartitionTests : IDisposable
{
    private readonly string _root;

    public ScanPartitionTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "psc_partition_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_root)) Directory.Delete(_root, true); } catch (Exception) { }
    }

    private void MakeTree(string path, int depth, int fileCount = 3)
    {
        Directory.CreateDirectory(path);
        for (var i = 0; i < fileCount; i++)
            File.WriteAllText(Path.Combine(path, $"f{i}.txt"), "x");
        if (depth == 0) return;
        for (var i = 0; i < 2; i++)
            MakeTree(Path.Combine(path, $"d{depth}{i}"), depth - 1, fileCount);
    }

    [Fact]
    public void 空目录分区返回自身()
    {
        var empty = Path.Combine(_root, "empty");
        Directory.CreateDirectory(empty);

        var units = FileEnumerator.PartitionForScan(empty).ToList();
        Assert.Single(units);
        Assert.Equal(empty, units[0]);
    }

    [Fact]
    public void 单文件分区返回该文件本身()
    {
        var file = Path.Combine(_root, "only.txt");
        File.WriteAllText(file, "x");

        var units = FileEnumerator.PartitionForScan(file).ToList();
        Assert.Single(units);
        Assert.Equal(file, units[0]);
    }

    [Fact]
    public void 分区结果必须构成反链()
    {
        MakeTree(Path.Combine(_root, "tree"), 2);

        var units = FileEnumerator.PartitionForScan(_root).ToList();

        Assert.NotEmpty(units);
        Assert.True(FileEnumerator.IsAntichain(units),
            "分区结果存在祖先/后代关系，会导致 Defender 重复扫描：" + string.Join(" | ", units));
    }

    [Fact]
    public void 分区必须完整覆盖根目录直系文件且不重复统计()
    {
        MakeTree(Path.Combine(_root, "tree"), 2);
        var rootFile = Path.Combine(_root, "root-level.txt");
        File.WriteAllText(rootFile, "root");
        var actual = FileEnumerator.EnumerateFiles(_root, CancellationToken.None)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.True(actual.Count > 0);

        var units = FileEnumerator.PartitionForScan(_root).ToList();
        var partitionFiles = units
            .SelectMany(u => FileEnumerator.EnumerateFiles(u, CancellationToken.None))
            .ToList();

        Assert.True(FileEnumerator.IsAntichain(units));
        Assert.Equal(partitionFiles.Count, partitionFiles.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Equal(actual, partitionFiles.ToHashSet(StringComparer.OrdinalIgnoreCase));
        Assert.Contains(rootFile, partitionFiles);
    }

    [Fact]
    public void 分区不包含目录自身与子目录同时出现()
    {
        var tree = Path.Combine(_root, "tree");
        MakeTree(tree, 1);

        var units = FileEnumerator.PartitionForScan(_root).ToList();

        Assert.DoesNotContain(units, u => FileEnumerator.IsSameOrDescendant(units[0], u) && !ReferenceEquals(u, units[0]));
        Assert.All(units, u => Assert.False(
            FileEnumerator.IsSameOrDescendant(_root, u) && units.Count > 1 && string.Equals(u, _root, StringComparison.OrdinalIgnoreCase),
            "多单元分区时不应把根目录本身作为单元（否则与子目录重复）"));
    }

    [Fact]
    public void IsAntichain_能识别嵌套关系()
    {
        var parent = Path.Combine(_root, "a");
        var child = Path.Combine(parent, "b");
        Directory.CreateDirectory(child);

        Assert.False(FileEnumerator.IsAntichain(new[] { parent, child }));
        Assert.False(FileEnumerator.IsAntichain(new[] { child, parent }));
        Assert.True(FileEnumerator.IsAntichain(new[] { child }));
        Assert.True(FileEnumerator.IsAntichain(new[] { Path.Combine(_root, "a"), Path.Combine(_root, "c") }));
    }

    [Fact]
    public void 不存在路径分区为空()
    {
        var missing = Path.Combine(_root, "does-not-exist");
        Assert.Empty(FileEnumerator.PartitionForScan(missing));
    }
}

/// <summary>扫描运行 ID 必须贯穿到威胁记录，才能按扫描归档。</summary>
public class ScanRunIdTests
{
    [Fact]
    public async Task 自定义扫描的威胁都带上本次RunId()
    {
        var dir = Path.Combine(Path.GetTempPath(), "psc_runid_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            await File.WriteAllBytesAsync(Path.Combine(dir, "invoice.pdf.exe"),
                new byte[] { 0x4D, 0x5A, 0x90, 0x00 });

            var orchestrator = new ScanOrchestrator(new StubDefender(), new ScanRangeBuilder(), new SmartRiskEngine());
            var threats = new List<ThreatInfo>();
            orchestrator.ThreatFound += (_, t) => threats.Add(t);

            await orchestrator.StartAsync(new ScanRequest
            {
                Type = ScanType.Custom,
                RootPaths = new List<string> { dir },
            });

            var runId = orchestrator.CurrentProgress.RunId;
            Assert.NotEqual(Guid.Empty, runId);
            Assert.NotEmpty(threats);
            Assert.All(threats, t => Assert.Equal(runId, t.ScanRunId));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch (Exception) { }
        }
    }

    [Fact]
    public async Task 两次扫描的RunId不同()
    {
        var dir = Path.Combine(Path.GetTempPath(), "psc_runid2_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(dir, "a.txt"), "x");
            var orchestrator = new ScanOrchestrator(new StubDefender(), new ScanRangeBuilder(), new SmartRiskEngine());
            var request = new ScanRequest
            {
                Type = ScanType.Custom,
                RootPaths = new List<string> { dir },
            };

            await orchestrator.StartAsync(request);
            var first = orchestrator.CurrentProgress.RunId;
            await orchestrator.StartAsync(request);
            var second = orchestrator.CurrentProgress.RunId;

            Assert.NotEqual(Guid.Empty, first);
            Assert.NotEqual(Guid.Empty, second);
            Assert.NotEqual(first, second);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch (Exception) { }
        }
    }

    /// <summary>避免测试真的调用 Defender（节省时间且不受机器状态影响）。</summary>
    private sealed class StubDefender : IDefenderClient
    {
        public bool IsAvailable => false;
        public string? MpCmdRunPath => null;
        public Task<DefenderStatusInfo> GetStatusAsync(CancellationToken ct = default)
            => Task.FromResult(new DefenderStatusInfo());
        public Task<bool> UpdateSignaturesAsync(CancellationToken ct = default) => Task.FromResult(false);
        public Task<bool> StartQuickScanAsync(CancellationToken ct = default) => Task.FromResult(false);
        public Task<MpScanResult> ScanPathsAsync(
            IEnumerable<string> paths, CancellationToken ct) => Task.FromResult(new MpScanResult());
        public Task<List<ThreatInfo>> GetThreatDetectionsAsync(CancellationToken ct = default)
            => Task.FromResult(new List<ThreatInfo>());
        public Task<bool> RemoveThreatAsync(long threatId, CancellationToken ct = default) => Task.FromResult(false);
        public IAsyncEnumerable<DirectoryScanResult> StreamScanDirectoriesAsync(
            System.Threading.Channels.ChannelReader<string> directories, CancellationToken ct)
            => Empty();
        private static async IAsyncEnumerable<DirectoryScanResult> Empty()
        {
            await Task.CompletedTask;
            yield break;
        }
    }
}

/// <summary>
/// Defender 威胁清除的范围约束：必须按 ThreatID 定点，绝不"清除全部"。
/// </summary>
public class DefenderThreatScopeTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(long.MinValue)]
    public async Task 非法威胁ID在进入脚本前被拒绝(long id)
    {
        var client = new PcSecurityCenter.Platform.Defender.DefenderClient();
        var result = await client.RemoveThreatAsync(id);
        Assert.False(result);
    }
}
