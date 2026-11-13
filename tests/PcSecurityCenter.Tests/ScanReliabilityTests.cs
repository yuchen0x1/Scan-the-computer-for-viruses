using System.Runtime.CompilerServices;
using System.Threading.Channels;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Core.Scanning;
using PcSecurityCenter.Data.Configuration;
using PcSecurityCenter.Platform.Security;
using Xunit;

namespace PcSecurityCenter.Tests;

public class ScanReliabilityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "psc_reliability_" + Guid.NewGuid().ToString("N"));
    public ScanReliabilityTests() => Directory.CreateDirectory(_root);
    public void Dispose() => Directory.Delete(_root, true);
    private string FileAt(string name)
    {
        var path = Path.Combine(_root, name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, "harmless fixture");
        return path;
    }
    private ScanOrchestrator Scanner(FakeDefender? defender = null, FakeEngine? engine = null)
        => new(defender ?? new(), new FakeRange(_root), engine ?? new());
    private ScanRequest Request(params string[] paths) => new() { Type = ScanType.Custom, RootPaths = paths.ToList() };

    [Fact]
    public async Task TwoEnginesAndOverlappingRoots_CountFilesOnce_KeepBothDetections()
    {
        var file = FileAt("child/a.txt");
        FileAt("b.txt");
        var defender = new FakeDefender { Detections = [new() { FilePath = file, Engine = "MicrosoftDefender", Name = "confirmed", Kind = DetectionKind.Confirmed }] };
        var scanner = Scanner(defender, new() { Detect = true });
        var threats = new List<ThreatInfo>();
        scanner.ThreatFound += (_, t) => threats.Add(t);
        await scanner.StartAsync(Request(file, _root, Path.Combine(_root, "child"), _root));
        Assert.Equal(2, scanner.CurrentProgress.FilesScanned);
        Assert.Equal(3, scanner.CurrentProgress.ThreatsFound);
        Assert.Contains(threats, t => t.Kind == DetectionKind.Confirmed);
        Assert.Single(defender.Paths);
        Assert.Equal(_root, scanner.CurrentProgress.Scope);
    }

    [Fact]
    public async Task FailedDefender_RemainsVisibleInCompletedSummary()
    {
        FileAt("a.txt");
        var scanner = Scanner(new() { ScanSuccess = false });
        await scanner.StartAsync(Request(_root));
        Assert.Equal(ScanState.Completed, scanner.CurrentProgress.State);
        Assert.Contains("覆盖受限", scanner.CurrentProgress.Message);
        Assert.Contains("Defender", scanner.CurrentProgress.CoverageWarnings);
        Assert.Equal(1, scanner.CurrentProgress.FilesScanned);
    }

    [Fact]
    public async Task MissingDefender_IsNotReportedAsFullCoverage()
    {
        FileAt("a.txt");
        var scanner = Scanner(new() { IsAvailable = false });
        await scanner.StartAsync(Request(_root));
        Assert.Contains("不可用", scanner.CurrentProgress.CoverageWarnings);
    }

    [Fact]
    public async Task EmptyScope_FailsInsteadOfCompletingClean()
    {
        var scanner = Scanner();
        await scanner.StartAsync(Request(Path.Combine(_root, "missing")));
        Assert.Equal(ScanState.Failed, scanner.CurrentProgress.State);
    }

    [Fact]
    public async Task RepeatedScan_ReemitsDetectionsWithNewRunId()
    {
        FileAt("a.txt");
        var scanner = Scanner(engine: new() { Detect = true });
        var ids = new List<Guid?>();
        scanner.ThreatFound += (_, t) => ids.Add(t.ScanRunId);
        await scanner.StartAsync(Request(_root));
        await scanner.StartAsync(Request(_root));
        Assert.Equal(2, ids.Distinct().Count());
    }

    [Fact]
    public async Task FullScan_EarlyConsumerExit_DoesNotHangProducer()
    {
        for (var i = 0; i < 15; i++) FileAt($"dir{i}/a.txt");
        var scanner = Scanner(new() { ExitStreamEarly = true });
        await scanner.StartAsync(new() { Type = ScanType.Full }).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Contains("提前结束", scanner.CurrentProgress.CoverageWarnings);
    }

    [Fact]
    public async Task FullScan_CountIsNotDoubledByDefender()
    {
        FileAt("a/x.txt"); FileAt("b/y.txt");
        var scanner = Scanner();
        await scanner.StartAsync(new() { Type = ScanType.Full });
        Assert.Equal(2, scanner.CurrentProgress.FilesScanned);
        Assert.Empty(scanner.CurrentProgress.CoverageWarnings);
    }

    [Fact]
    public async Task CancelledScan_CanRestart_RejectsConcurrentStart()
    {
        FileAt("a.txt");
        var engine = new FakeEngine { Block = true };
        var scanner = Scanner(engine: engine);
        var run = scanner.StartAsync(Request(_root));
        await engine.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAsync<InvalidOperationException>(() => scanner.StartAsync(Request(_root)));
        await scanner.CancelAsync();
        await run.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(ScanState.Cancelled, scanner.CurrentProgress.State);
        engine.Block = false;
        await scanner.StartAsync(Request(_root));
        Assert.Equal(ScanState.Completed, scanner.CurrentProgress.State);
    }

    [Fact]
    public void DriveRootContainment_AndSiblingPrefix_AreCorrect()
    {
        var drive = Path.GetPathRoot(_root)!;
        Assert.True(FileEnumerator.IsSameOrDescendant(_root, drive));
        Assert.False(FileEnumerator.IsSameOrDescendant(_root + "extra", _root));
        Assert.Single(FileEnumerator.NormalizeRoots([_root, drive, _root]));
    }

    [Fact]
    public async Task Config_ConcurrentSave_AlwaysProducesReadableJson()
    {
        var path = Path.Combine(_root, "config.json");
        var service = new ConfigService(path);
        service.Current.MaxLogDays = 91;
        var saved = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => service.SaveAsync()));
        Assert.All(saved, Assert.True);
        var loaded = new ConfigService(path);
        await loaded.LoadAsync();
        Assert.Equal(91, loaded.Current.MaxLogDays);
        Assert.Empty(Directory.GetFiles(_root, "*.tmp"));
    }

    [Fact]
    public async Task Config_FailedReplacement_PreservesOriginal()
    {
        var path = Path.Combine(_root, "config.json");
        var service = new ConfigService(path);
        Assert.True(await service.SaveAsync());
        var original = File.ReadAllText(path);
        using var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        service.Current.MaxLogDays = 99;
        Assert.False(await service.SaveAsync());
        Assert.Equal(original, File.ReadAllText(path));
    }

    [Fact]
    public async Task ConcurrentQuarantines_RetainAllRecordsAndRestorableContent()
    {
        var vault = new QuarantineService(Path.Combine(_root, "vault"));
        var paths = Enumerable.Range(0, 12).Select(i => FileAt($"files/{i}.txt")).ToArray();
        await Task.WhenAll(paths.Select(p => vault.QuarantineFileAsync(p, "fixture", "test", ThreatSeverity.Low)));
        var entries = await vault.ListAsync();
        Assert.Equal(paths.Length, entries.Count);
        Assert.All(paths, p => Assert.False(File.Exists(p)));
        foreach (var entry in entries) Assert.True(await vault.RestoreAsync(entry.Id));
        Assert.All(paths, p => Assert.Equal("harmless fixture", File.ReadAllText(p)));
    }

    [Fact]
    public async Task DefenderSelectiveRemoval_RejectsPositiveIdsToo()
    {
        var defender = new PcSecurityCenter.Platform.Defender.DefenderClient();
        Assert.False(await defender.RemoveThreatAsync(12345));
    }

    private sealed class FakeRange(string root) : IScanRangeBuilder
    {
        public List<string> BuildQuickRange() => [root];
        public List<string> BuildFullRange(IEnumerable<string>? drives = null) => [root];
        public Task<long> EstimateFileCountAsync(IEnumerable<string> roots, CancellationToken ct)
            => Task.FromResult(roots.Sum(r => FileEnumerator.EnumerateFiles(r, ct).LongCount()));
    }
    private sealed class FakeEngine : IScanEngine
    {
        public string Name => "Fixture";
        public bool IsAvailable => true;
        public bool Detect { get; init; }
        public bool Block { get; set; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async IAsyncEnumerable<ThreatInfo> ScanFilesAsync(IReadOnlyList<string> files, ScanContext context, [EnumeratorCancellation] CancellationToken ct)
        {
            Entered.TrySetResult();
            if (Block) await Task.Delay(Timeout.Infinite, ct);
            foreach (var file in files)
                if (Detect) yield return new() { FilePath = file, Name = "rule", Engine = "SmartRisk" };
        }
    }
    private sealed class FakeDefender : IDefenderClient
    {
        public bool IsAvailable { get; init; } = true;
        public string? MpCmdRunPath => null;
        public bool ScanSuccess { get; init; } = true;
        public bool ExitStreamEarly { get; init; }
        public List<string> Paths { get; } = [];
        public List<ThreatInfo> Detections { get; init; } = [];
        public Task<DefenderStatusInfo> GetStatusAsync(CancellationToken ct = default) => Task.FromResult(new DefenderStatusInfo());
        public Task<bool> UpdateSignaturesAsync(CancellationToken ct = default) => Task.FromResult(false);
        public Task<bool> StartQuickScanAsync(CancellationToken ct = default) => Task.FromResult(ScanSuccess);
        public Task<MpScanResult> ScanPathsAsync(IEnumerable<string> paths, CancellationToken ct)
        {
            Paths.AddRange(paths);
            return Task.FromResult(new MpScanResult { Success = ScanSuccess, Error = ScanSuccess ? "" : "fixture failure" });
        }
        public Task<List<ThreatInfo>> GetThreatDetectionsAsync(CancellationToken ct = default) => Task.FromResult(Detections);
        public Task<bool> RemoveThreatAsync(long threatId, CancellationToken ct = default) => Task.FromResult(false);
        public async IAsyncEnumerable<DirectoryScanResult> StreamScanDirectoriesAsync(ChannelReader<string> directories, [EnumeratorCancellation] CancellationToken ct)
        {
            if (ExitStreamEarly) yield break;
            await foreach (var path in directories.ReadAllAsync(ct))
                yield return new() { Directory = path, Success = ScanSuccess, FileCount = 100 };
        }
    }
}
