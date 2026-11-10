using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Core.Scanning;
using PcSecurityCenter.Core.SecurityChecks;
using PcSecurityCenter.Platform.Defender;
using Xunit;

namespace PcSecurityCenter.Tests;

/// <summary>扫描命令编排：直接调用（绕过 UI），验证编排器真实工作。</summary>
public class ScanOrchestratorTests
{
    [Fact]
    public async Task QuickScan_RunsEngines_AndCompletes()
    {
        var defender = new DefenderClient();
        var orchestrator = new ScanOrchestrator(defender, new ScanRangeBuilder(), new SmartRiskEngine());
        var completed = new TaskCompletionSource<ScanProgress>(TaskCreationOptions.RunContinuationsAsynchronously);
        var threats = new List<ThreatInfo>();
        orchestrator.Completed += (_, p) => completed.TrySetResult(p);
        orchestrator.ThreatFound += (_, t) => threats.Add(t);

        await orchestrator.StartAsync(new ScanRequest { Type = ScanType.Quick });

        var final = await completed.Task.WaitAsync(TimeSpan.FromMinutes(12));
        Assert.True(final.FilesScanned > 0, $"快速扫描应检查到文件（实际 {final.FilesScanned}）");
        Assert.True(final.State is ScanState.Completed or ScanState.Failed,
            $"最终状态 {final.State}；消息：{final.Message}");
        // 若 Defender 可用，原生快速扫描应该已被触发（结果记录在数据库/Defender 自身）
        if (defender.IsAvailable)
        {
            // 快扫会拉取真实威胁记录（可能为空），不做数量断言，只验证流程不崩
            Assert.NotEqual(ScanState.Failed, final.State);
        }
    }

    [Fact]
    public async Task CustomScan_OnTestDir_DetectsPlantedRisk()
    {
        // 在隔离的测试目录里放置一个双扩展名文件，验证自定义扫描真实检出
        var dir = Path.Combine(Path.GetTempPath(), "psc_e2e_scan_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        try
        {
            await File.WriteAllBytesAsync(Path.Combine(dir, "invoice.pdf.exe"),
                new byte[] { 0x4D, 0x5A, 0x90, 0x00, 0x01, 0x02, 0x03 });

            var defender = new DefenderClient();
            var orchestrator = new ScanOrchestrator(defender, new ScanRangeBuilder(), new SmartRiskEngine());
            var completed = new TaskCompletionSource<ScanProgress>(TaskCreationOptions.RunContinuationsAsynchronously);
            var threats = new List<ThreatInfo>();
            orchestrator.Completed += (_, p) => completed.TrySetResult(p);
            orchestrator.ThreatFound += (_, t) => threats.Add(t);

            await orchestrator.StartAsync(new ScanRequest { Type = ScanType.Custom, RootPaths = new List<string> { dir } });

            var final = await completed.Task.WaitAsync(TimeSpan.FromMinutes(5));
            Assert.Contains(threats, t => t.FilePath.Contains("invoice.pdf.exe") && t.Engine == "SmartRisk");
            Assert.True(final.ThreatsFound >= 1, $"应至少检出植入样本（实际 {final.ThreatsFound}）");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch (Exception) { }
        }
    }

    [Fact]
    public async Task Cancel_StopsRunningScan()
    {
        var defender = new DefenderClient();
        var orchestrator = new ScanOrchestrator(defender, new ScanRangeBuilder(), new SmartRiskEngine());
        var completed = new TaskCompletionSource<ScanProgress>(TaskCreationOptions.RunContinuationsAsynchronously);
        orchestrator.Completed += (_, p) => completed.TrySetResult(p);

        // StartAsync owns the scan lifecycle and completes only when the scan ends.
        // Keep its task in the background so cancellation can be requested while
        // the operation is actually running.
        var scanTask = orchestrator.StartAsync(new ScanRequest { Type = ScanType.Quick });
        await Task.Delay(3000);
        await orchestrator.CancelAsync();

        await scanTask.WaitAsync(TimeSpan.FromMinutes(6));
        var final = await completed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(final.State is ScanState.Cancelled or ScanState.Completed,
            $"取消后状态应为 Cancelled（或已完成），实际 {final.State}");
    }
}
