using System.Threading.Channels;
using Serilog;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;

namespace PcSecurityCenter.Core.Scanning;

/// <summary>
/// 扫描编排器（真实引擎调度核心）：
/// - 快速扫描：Defender 原生快速扫描 + 智能风险引擎扫描快速范围。
/// - 全盘扫描：按二级目录分批交给 Defender 逐目录流式扫描（原生引擎逐目录执行），
///   通过"生产者-消费者 + 暂停门"实现真实的暂停/恢复/取消与进度统计。
/// - 自定义扫描：对用户选择的目录/文件执行 Defender MpCmdRun 定向扫描 + 智能风险引擎。
/// 所有结果均来自真实引擎，不生成任何伪造数据。
/// </summary>
public class ScanOrchestrator : IScanOrchestrator
{
    private readonly IDefenderClient _defender;
    private readonly IScanRangeBuilder _rangeBuilder;
    private readonly IScanEngine _smartEngine;
    private readonly object _gate = new();

    private CancellationTokenSource? _cts;
    private volatile bool _paused;
    private readonly SemaphoreSlim _pauseGate = new(1, 1);

    public ScanProgress CurrentProgress { get; } = new();
    public event EventHandler<ScanProgress>? ProgressChanged;
    public event EventHandler<ThreatInfo>? ThreatFound;
    public event EventHandler<ScanProgress>? Completed;

    public ScanOrchestrator(IDefenderClient defender, IScanRangeBuilder rangeBuilder, IScanEngine smartEngine)
    {
        _defender = defender;
        _rangeBuilder = rangeBuilder;
        _smartEngine = smartEngine;
    }

    private void Update(Action<ScanProgress> mutate)
    {
        lock (_gate) mutate(CurrentProgress);
        ProgressChanged?.Invoke(this, Snapshot());
    }

    public ScanProgress Snapshot()
    {
        lock (_gate)
        {
            return new ScanProgress
            {
                State = CurrentProgress.State,
                Type = CurrentProgress.Type,
                CurrentItem = CurrentProgress.CurrentItem,
                FilesTotal = CurrentProgress.FilesTotal,
                FilesScanned = CurrentProgress.FilesScanned,
                FilesPerSecond = CurrentProgress.FilesPerSecond,
                ThreatsFound = CurrentProgress.ThreatsFound,
                Elapsed = CurrentProgress.Elapsed,
                EngineName = CurrentProgress.EngineName,
                Message = CurrentProgress.Message,
            };
        }
    }

    public async Task StartAsync(ScanRequest request)
    {
        if (CurrentProgress.State is ScanState.Running or ScanState.Preparing or ScanState.Paused)
            throw new InvalidOperationException("已有扫描任务在运行中。");

        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _paused = false;
        var startedAt = DateTime.UtcNow;
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 整个流程包在 try 中：任何异常都要落到 UI 与日志，绝不允许被命令层静默吞掉
        try
        {
            // 探针可能同步等待 PowerShell（首次冷启动），放到线程池避免冻结 UI
            var defenderAvailable = await Task.Run(() => _defender.IsAvailable, ct);

            Update(p =>
            {
                p.State = ScanState.Preparing;
                p.Type = request.Type;
                p.FilesScanned = 0;
                p.FilesTotal = 0;
                p.ThreatsFound = 0;
                p.Elapsed = TimeSpan.Zero;
                p.Message = "正在准备扫描范围…";
                p.EngineName = defenderAvailable ? "Microsoft Defender + SmartRisk" : "SmartRisk（Defender 不可用）";
            });
            // 范围
            var roots = request.Type switch
            {
                ScanType.Quick => _rangeBuilder.BuildQuickRange(),
                ScanType.Full => _rangeBuilder.BuildFullRange(request.Drives.Count > 0 ? request.Drives : null),
                _ => request.RootPaths.Where(p => Directory.Exists(p) || File.Exists(p)).ToList(),
            };
            Serilog.Log.Information("扫描开始：类型 {Type}，范围 {Scope}，Defender={Defender}",
                request.Type, string.Join(";", roots.Take(5)), defenderAvailable);

            var scopeText = string.Join("；", roots.Take(6)) + (roots.Count > 6 ? $" 等 {roots.Count} 个位置" : "");
            Update(p => { p.Message = $"扫描范围：{scopeText}"; });

            // 防护提示：Defender 不可用时的诚实提示
            if (!defenderAvailable)
                Update(p => p.Message = "警告：Microsoft Defender 不可用，本扫描仅启用智能风险规则引擎，病毒判定能力受限。");

            // 后台估算文件总数（供进度显示；尽力而为，不阻塞扫描开始）
            var estimateCts = CancellationTokenSource.CreateLinkedTokenSource(ct, new CancellationTokenSource(120_000).Token);
            var estimateTask = _rangeBuilder.EstimateFileCountAsync(roots, estimateCts.Token);

            Update(p => { p.State = ScanState.Running; p.Message = "扫描进行中…"; });

            // 智能引擎产出
            var smartTask = Task.Run(() => RunSmartEngineAsync(roots, contextFor(request), found, startedAt, ct), ct);

            // Defender 部分
            Task defenderTask = request.Type switch
            {
                ScanType.Quick => RunDefenderQuickAsync(found, startedAt, ct),
                ScanType.Full => RunDefenderStreamedAsync(roots, found, startedAt, ct, estimateTask),
                _ => RunDefenderCustomAsync(roots, found, startedAt, ct),
            };

            await Task.WhenAll(smartTask, defenderTask);
            await estimateTask.IgnoreCancellation();

            var threats = found.Count;
            Serilog.Log.Information("扫描完成：文件 {Files}，风险 {Threats}，耗时 {Elapsed}",
                CurrentProgress.FilesScanned, threats, DateTime.UtcNow - startedAt);
            Update(p => { p.State = ScanState.Completed; p.Message = $"扫描完成：共检查 {p.FilesScanned} 个文件，发现 {threats} 项风险。"; });
        }
        catch (OperationCanceledException)
        {
            Serilog.Log.Information("扫描已取消");
            Update(p => { p.State = ScanState.Cancelled; p.Message = "扫描已取消。"; });
        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "扫描失败");
            Update(p => { p.State = ScanState.Failed; p.Message = $"扫描失败：{ex.Message}"; });
        }
        finally
        {
            Update(p => p.Elapsed = DateTime.UtcNow - startedAt);
            Completed?.Invoke(this, Snapshot());
        }
    }

    private static ScanContext contextFor(ScanRequest request) => new()
    {
        Type = request.Type,
        ScanRunId = Guid.NewGuid(),
        RootPaths = request.RootPaths,
    };

    // ---------- 智能引擎（范围文件 → 规则检测） ----------
    private async Task RunSmartEngineAsync(List<string> roots, ScanContext ctx,
        HashSet<string> found, DateTime startedAt, CancellationToken ct)
    {
        var files = new List<string>(512);
        foreach (var root in roots)
        {
            foreach (var f in FileEnumerator.EnumerateFiles(root, ct))
            {
                ct.ThrowIfCancellationRequested();
                await WaitWhilePausedAsync(ct);
                files.Add(f);
                if (files.Count >= 512)
                {
                    await ScanFileBatchAsync(files, ctx, found, startedAt, ct);
                    files.Clear();
                }
            }
        }
        if (files.Count > 0)
            await ScanFileBatchAsync(files, ctx, found, startedAt, ct);
    }

    private async Task ScanFileBatchAsync(List<string> files, ScanContext ctx,
        HashSet<string> found, DateTime startedAt, CancellationToken ct)
    {
        await foreach (var t in _smartEngine.ScanFilesAsync(files, ctx, ct))
        {
            if (found.Add(t.FilePath))
            {
                lock (_gate) CurrentProgress.ThreatsFound++;
                ThreatFound?.Invoke(this, t);
            }
        }
        lock (_gate) CurrentProgress.FilesScanned += files.Count;
        UpdateTiming(startedAt);
        Update(p => { });
        // 批间让出调度：控制 CPU 占用（每 512 文件约让出 30ms）
        await Task.Delay(30, ct);
    }

    private void UpdateTiming(DateTime startedAt)
    {
        lock (_gate)
        {
            CurrentProgress.Elapsed = DateTime.UtcNow - startedAt;
            CurrentProgress.FilesPerSecond = CurrentProgress.Elapsed.TotalSeconds > 0.5
                ? CurrentProgress.FilesScanned / CurrentProgress.Elapsed.TotalSeconds : 0;
            if (CurrentProgress.FilesScanned > CurrentProgress.FilesTotal)
                CurrentProgress.FilesTotal = CurrentProgress.FilesScanned;
        }
    }

    private async Task WaitWhilePausedAsync(CancellationToken ct)
    {
        while (_paused && !ct.IsCancellationRequested)
        {
            Update(p => { if (p.State == ScanState.Running) p.State = ScanState.Paused; });
            await Task.Delay(200, ct);
        }
        Update(p => { if (p.State == ScanState.Paused) p.State = ScanState.Running; });
    }

    // ---------- Defender：快速扫描（原生） ----------
    private async Task RunDefenderQuickAsync(HashSet<string> found, DateTime startedAt, CancellationToken ct)
    {
        if (!_defender.IsAvailable) return;
        Update(p => p.CurrentItem = "Defender 原生快速扫描（系统内存与启动区域）");
        Serilog.Log.Information("启动 Defender 原生快速扫描…");
        var ok = await _defender.StartQuickScanAsync(ct);
        Serilog.Log.Information("Defender 原生快速扫描结束：{Result}", ok ? "完成" : "未成功");
        if (!ok)
            Update(p => p.Message = "Defender 快速扫描未能启动（详见日志），已继续使用智能风险引擎。");
        // 等原生扫描收尾后拉取真实检测记录
        await Task.Delay(1500, ct);
        await CollectDefenderDetectionsAsync(found, ct, startedAt.ToLocalTime());
    }

    // ---------- Defender：全盘（流式逐目录，支持暂停/恢复/取消） ----------
    private async Task RunDefenderStreamedAsync(List<string> roots, HashSet<string> found,
        DateTime startedAt, CancellationToken ct, Task<long> estimateTask)
    {
        if (!_defender.IsAvailable) return;

        var dirChannel = Channel.CreateBounded<string>(new BoundedChannelOptions(4) { SingleReader = false });
        var estimate = 0L;
        _ = Task.Run(async () =>
        {
            try { estimate = await estimateTask; lock (_gate) CurrentProgress.FilesTotal = estimate; }
            catch (Exception) { }
        }, ct);

        // 生产者：产出待扫描目录（二级粒度），经过暂停门实现真实暂停
        var producer = Task.Run(async () =>
        {
            try
            {
                foreach (var root in roots)
                {
                    foreach (var dir in FileEnumerator.EnumerateDirectoriesShallow(root))
                    {
                        foreach (var sub in FileEnumerator.EnumerateDirectoriesShallow(dir))
                        {
                            await WaitWhilePausedAsync(ct);
                            await _pauseGate.WaitAsync(ct);
                            try { await dirChannel.Writer.WriteAsync(sub, ct); }
                            finally { _pauseGate.Release(); }
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
            finally { dirChannel.Writer.TryComplete(); }
        }, ct);

        var batchStart = DateTime.Now;
        var dirResults = _defender.StreamScanDirectoriesAsync(dirChannel.Reader, ct);

        await foreach (var r in dirResults.WithCancellation(ct))
        {
            ct.ThrowIfCancellationRequested();
            lock (_gate) CurrentProgress.FilesScanned += r.FileCount;
            UpdateTiming(startedAt);
            Update(p => p.CurrentItem = $"Defender 引擎扫描：{r.Directory}");
            foreach (var d in r.NewDetections)
                if (found.Add(d.FilePath))
                {
                    lock (_gate) CurrentProgress.ThreatsFound++;
                    ThreatFound?.Invoke(this, d);
                }
            // 随时间细化总量估计
            if (estimate > 0)
                lock (_gate) CurrentProgress.FilesTotal = Math.Max(CurrentProgress.FilesScanned,
                    Math.Min(estimate, CurrentProgress.FilesScanned + 5000));
            batchStart = DateTime.Now;
        }
        await producer;
    }

    // ---------- Defender：自定义扫描（MpCmdRun 定向） ----------
    private async Task RunDefenderCustomAsync(List<string> roots, HashSet<string> found, DateTime startedAt, CancellationToken ct)
    {
        if (!_defender.IsAvailable) return;
        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();
            await WaitWhilePausedAsync(ct);
            Update(p => { p.CurrentItem = $"Defender 定向扫描：{root}"; });
            var result = await _defender.ScanPathsAsync(new[] { root }, ct);
            if (result.ThreatsFound > 0)
            {
                foreach (var t in result.ThreatList)
                    Update(p => p.Message = $"Defender 检出：{t}");
            }
            // 定向扫描后拉取真实检测记录
            await CollectDefenderDetectionsAsync(found, ct, startedAt.ToLocalTime());
            var count = await CountFilesAsync(root, ct);
            lock (_gate) CurrentProgress.FilesScanned += count;
            UpdateTiming(startedAt);
            Update(p => { });
        }
    }

    private static async Task<long> CountFilesAsync(string root, CancellationToken ct)
    {
        return await Task.Run(() => FileEnumerator.EnumerateFiles(root, ct).LongCount(), ct);
    }

    private async Task CollectDefenderDetectionsAsync(HashSet<string> found, CancellationToken ct, DateTime? since = null)
    {
        try
        {
            var detections = await _defender.GetThreatDetectionsAsync(ct);
            foreach (var d in detections)
            {
                // 只归因于本次扫描期间（或之后）的检出，避免把历史记录算进本次结果
                if (since != null && d.DetectedAt < since.Value.AddSeconds(-5)) continue;
                if (found.Add(d.FilePath))
                {
                    lock (_gate) CurrentProgress.ThreatsFound++;
                    ThreatFound?.Invoke(this, d);
                }
            }
        }
        catch (Exception) { /* 检测记录读取失败不阻断扫描 */ }
    }

    public void Pause()
    {
        if (CurrentProgress.State != ScanState.Running) return;
        _paused = true;
        Update(p => { p.State = ScanState.Paused; p.Message = "已暂停（当前目录扫描完成后暂停，继续时从下一目录开始）。"; });
    }

    public void Resume()
    {
        if (CurrentProgress.State != ScanState.Paused) return;
        _paused = false;
    }

    public async Task CancelAsync()
    {
        if (CurrentProgress.State is not (ScanState.Running or ScanState.Paused or ScanState.Preparing)) return;
        Update(p => { p.State = ScanState.Cancelling; p.Message = "正在取消扫描…"; });
        try
        {
            if (_defender.IsAvailable) await _defender.StopScanAsync();
        }
        catch (Exception) { }
        _cts?.Cancel();
    }
}

public static class TaskExtensions
{
    /// <summary>忽略估算任务被取消/失败，不影响主扫描。</summary>
    public static async Task IgnoreCancellation(this Task task)
    {
        try { await task; }
        catch (OperationCanceledException) { }
        catch (Exception) { }
    }
}
