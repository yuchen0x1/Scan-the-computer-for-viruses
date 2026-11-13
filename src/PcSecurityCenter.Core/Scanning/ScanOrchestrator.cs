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
    private readonly IConfigService? _config;
    private readonly object _gate = new();

    private CancellationTokenSource? _cts;
    private volatile bool _paused;
    private readonly HashSet<string> _warnings = new();

    public ScanProgress CurrentProgress { get; } = new();
    public event EventHandler<ScanProgress>? ProgressChanged;
    public event EventHandler<ThreatInfo>? ThreatFound;
    public event EventHandler<ScanProgress>? Completed;

    public ScanOrchestrator(IDefenderClient defender, IScanRangeBuilder rangeBuilder, IScanEngine smartEngine,
        IConfigService? config = null)
    {
        _defender = defender;
        _rangeBuilder = rangeBuilder;
        _smartEngine = smartEngine;
        _config = config;
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
                RunId = CurrentProgress.RunId,
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
                CoverageWarnings = CurrentProgress.CoverageWarnings,
                Scope = CurrentProgress.Scope,
                IsEstimating = CurrentProgress.IsEstimating,
            };
        }
    }

    public async Task StartAsync(ScanRequest request)
    {
        CancellationTokenSource runCts;
        // 本次扫描的唯一标识：贯穿威胁记录、扫描记录与上下文，
        // 使「这次扫描发现了什么」可被 SQL 关联验证（此前上下文与记录各生成一个 Guid，永远对不上）。
        var runId = Guid.NewGuid();
        lock (_gate)
        {
            if (_cts != null)
                throw new InvalidOperationException("已有扫描任务在运行中。");

            runCts = new CancellationTokenSource();
            _cts = runCts;
            CurrentProgress.State = ScanState.Preparing;
            CurrentProgress.Type = request.Type;
            CurrentProgress.RunId = runId;
            CurrentProgress.FilesTotal = 0;
            CurrentProgress.FilesScanned = 0;
            CurrentProgress.FilesPerSecond = 0;
            CurrentProgress.ThreatsFound = 0;
            CurrentProgress.Elapsed = TimeSpan.Zero;
            CurrentProgress.CurrentItem = string.Empty;
            CurrentProgress.Message = string.Empty;
            CurrentProgress.EngineName = string.Empty;
            CurrentProgress.CoverageWarnings = string.Empty;
            CurrentProgress.Scope = string.Empty;
            CurrentProgress.IsEstimating = true;
            _warnings.Clear();
        }
        var ct = runCts.Token;
        _paused = false;
        var startedAt = DateTime.UtcNow;
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        CancellationTokenSource? estimateCts = null;
        Task? estimateObserver = null;

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
            roots = FileEnumerator.NormalizeRoots(roots);
            if (roots.Count == 0) throw new InvalidOperationException("没有可访问的扫描路径，请重新选择文件或文件夹。");
            if (request.Type == ScanType.Custom && request.RootPaths.Any(p => !File.Exists(p) && !Directory.Exists(p)))
                AddWarning("部分所选路径不存在或不可访问，未扫描这些路径。");
            Serilog.Log.Information("扫描开始：类型 {Type}，范围 {Scope}，Defender={Defender}",
                request.Type, string.Join(";", roots.Take(5)), defenderAvailable);

            var scopeText = string.Join("；", roots.Take(6)) + (roots.Count > 6 ? $" 等 {roots.Count} 个位置" : "");
            Update(p => { p.Scope = scopeText; p.Message = $"扫描范围：{scopeText}"; });

            // 防护提示：Defender 不可用时的诚实提示
            if (!defenderAvailable)
                AddWarning("Microsoft Defender 不可用，仅运行 SmartRisk 规则，未完成病毒引擎扫描。");

            // 后台估算文件总数（供进度显示；尽力而为，不阻塞扫描开始）
            estimateCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            estimateCts.CancelAfter(TimeSpan.FromMinutes(2));
            var estimateTask = Task.Run(() => _rangeBuilder.EstimateFileCountAsync(roots, estimateCts.Token));
            estimateObserver = ObserveEstimateAsync(estimateTask);

            Update(p => { p.State = ScanState.Running; p.Message = "扫描进行中…"; });

            // 智能引擎产出
            var smartTask = Task.Run(() => RunSmartEngineAsync(roots, contextFor(request, roots, runId), found, startedAt, ct, runId), ct);

            // Defender 部分
            Task defenderTask = !defenderAvailable ? Task.CompletedTask : request.Type switch
            {
                ScanType.Quick => RunDefenderQuickAsync(found, startedAt, ct, runId),
                ScanType.Full => RunDefenderStreamedAsync(roots, found, startedAt, ct, runId),
                _ => RunDefenderCustomAsync(roots, found, startedAt, ct, runId),
            };

            await Task.WhenAll(smartTask, defenderTask);
            estimateCts.Cancel();
            await estimateObserver;
            ct.ThrowIfCancellationRequested();

            var threats = found.Count;
            Serilog.Log.Information("扫描完成：文件 {Files}，风险 {Threats}，耗时 {Elapsed}",
                CurrentProgress.FilesScanned, threats, DateTime.UtcNow - startedAt);
            Update(p => { p.State = ScanState.Completed; p.Message = $"{(string.IsNullOrEmpty(p.CoverageWarnings) ? "扫描完成" : "扫描结束（覆盖受限）")}：已枚举 {p.FilesScanned} 个文件，发现 {threats} 条检测记录。"; });
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
            estimateCts?.Cancel();
            if (estimateObserver != null) await estimateObserver;
            Update(p => { p.Elapsed = DateTime.UtcNow - startedAt; p.IsEstimating = false; });
            var final = Snapshot();
            lock (_gate)
            {
                if (ReferenceEquals(_cts, runCts)) _cts = null;
                runCts.Dispose();
            }
            estimateCts?.Dispose();
            Completed?.Invoke(this, final);
        }
    }

    private async Task ObserveEstimateAsync(Task<long> estimate)
    {
        try
        {
            var count = await estimate;
            Update(p => p.FilesTotal = Math.Max(p.FilesTotal, count));
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { Log.Debug(ex, "文件数估算未完成"); }
        finally { Update(p => p.IsEstimating = false); }
    }

    private void AddWarning(string warning)
    {
        lock (_gate)
        {
            // 数量有界，逐目录失败不让 UI/报告无限增长。
            if (_warnings.Count < 12) _warnings.Add(warning);
            CurrentProgress.CoverageWarnings = string.Join("\n", _warnings);
        }
        Update(_ => { });
    }

    private void PublishDetection(ThreatInfo threat, HashSet<string> found, Guid runId)
    {
        threat.ScanRunId = runId;
        var key = $"{threat.Engine}|{threat.FilePath}|{threat.DefenderThreatId}|{threat.Name}";
        lock (_gate)
        {
            if (!found.Add(key)) return;
            CurrentProgress.ThreatsFound++;
            // 串行派发，消费者不必承担两个引擎并发事件的竞态。
            ThreatFound?.Invoke(this, threat);
        }
    }

    private ScanContext contextFor(ScanRequest request, IReadOnlyList<string> roots, Guid runId) => new()
    {
        Type = request.Type,
        ScanRunId = runId,
        RootPaths = roots,
        ExcludedPaths = ParseExclusions(_config?.Current.ScanExclusions),
    };

    private static IReadOnlyList<string> ParseExclusions(string? raw)
    {
        var result = new List<string>();
        foreach (var item in (raw ?? string.Empty).Split(new[] { '\r', '\n', ';' },
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try { result.Add(Path.GetFullPath(item)); }
            catch (Exception) { Log.Debug("忽略无效扫描排除路径：{Path}", item); }
        }
        return result.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    // ---------- 智能引擎（范围文件 → 规则检测） ----------
    private async Task RunSmartEngineAsync(List<string> roots, ScanContext ctx,
        HashSet<string> found, DateTime startedAt, CancellationToken ct, Guid runId)
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
                    await ScanFileBatchAsync(files, ctx, found, startedAt, ct, runId);
                    files.Clear();
                }
            }
        }
        if (files.Count > 0)
            await ScanFileBatchAsync(files, ctx, found, startedAt, ct, runId);
    }

    private async Task ScanFileBatchAsync(List<string> files, ScanContext ctx,
        HashSet<string> found, DateTime startedAt, CancellationToken ct, Guid runId)
    {
        await foreach (var t in _smartEngine.ScanFilesAsync(files, ctx, ct))
        {
            PublishDetection(t, found, runId);
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
    private async Task RunDefenderQuickAsync(HashSet<string> found, DateTime startedAt, CancellationToken ct, Guid runId)
    {
        Update(p => p.CurrentItem = "Defender 原生快速扫描（系统内存与启动区域）");
        Serilog.Log.Information("启动 Defender 原生快速扫描…");
        var ok = await _defender.StartQuickScanAsync(ct);
        Serilog.Log.Information("Defender 原生快速扫描结束：{Result}", ok ? "完成" : "未成功");
        if (!ok)
            AddWarning("Defender 快速扫描未成功，病毒引擎覆盖不完整（详见日志）。");
        // 等原生扫描收尾后拉取真实检测记录
        await Task.Delay(1500, ct);
        await CollectDefenderDetectionsAsync(found, ct, startedAt.ToLocalTime(), runId);
    }

    // ---------- Defender：全盘（流式逐目录，支持暂停/恢复/取消） ----------
    private async Task RunDefenderStreamedAsync(List<string> roots, HashSet<string> found,
        DateTime startedAt, CancellationToken ct,
        Guid runId)
    {

        // SingleReader：只有编排器一个读取者。反链分区保证每个目录只被投递一次，
        // 因此 Defender 不会重复递归扫描同一子树（见 FileEnumerator.PartitionForScan）。
        var dirChannel = Channel.CreateBounded<string>(new BoundedChannelOptions(4) { SingleReader = true });
        using var streamCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var streamToken = streamCts.Token;
        var submitted = 0;
        var received = 0;
        var allSubmitted = false;
        // 生产者：把每个根切分为互不包含的扫描单元；暂停通过 WaitWhilePausedAsync 实现
        var producer = Task.Run(async () =>
        {
            try
            {
                foreach (var root in roots)
                {
                    foreach (var unit in FileEnumerator.PartitionForScan(root))
                    {
                        await WaitWhilePausedAsync(streamToken);
                        await dirChannel.Writer.WriteAsync(unit, streamToken);
                        Interlocked.Increment(ref submitted);
                    }
                }
                allSubmitted = true;
            }
            catch (OperationCanceledException) when (streamToken.IsCancellationRequested) { }
            catch (Exception ex) { dirChannel.Writer.TryComplete(ex); throw; }
            finally { dirChannel.Writer.TryComplete(); }
        });

        try
        {
            await foreach (var r in _defender.StreamScanDirectoriesAsync(dirChannel.Reader, streamToken).WithCancellation(streamToken))
            {
                ct.ThrowIfCancellationRequested();
                received++;
                if (!r.Success) AddWarning($"Defender 未完成目录扫描：{r.Directory}；{r.Error}");
                UpdateTiming(startedAt);
                Update(p => p.CurrentItem = $"Defender 引擎扫描：{r.Directory}");
                foreach (var d in r.NewDetections) PublishDetection(d, found, runId);
            }
            // 消费者提前退出时先停止生产者，防有界队列满后永久等待。
            streamCts.Cancel();
            await producer;
            ct.ThrowIfCancellationRequested();
            if (!allSubmitted || submitted == 0 || received != submitted)
                AddWarning("Defender 目录扫描提前结束，部分扫描单元未返回结果。");
        }
        finally
        {
            streamCts.Cancel();
            await producer;
        }
    }

    // ---------- Defender：自定义扫描（MpCmdRun 定向） ----------
    private async Task RunDefenderCustomAsync(List<string> roots, HashSet<string> found,
        DateTime startedAt, CancellationToken ct, Guid runId)
    {
        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();
            await WaitWhilePausedAsync(ct);
            Update(p => { p.CurrentItem = $"Defender 定向扫描：{root}"; });
            var result = await _defender.ScanPathsAsync(new[] { root }, ct);
            if (!result.Success) AddWarning($"Defender 未完成定向扫描：{root}；{result.Error}");
            if (result.ThreatsFound > 0)
            {
                foreach (var t in result.ThreatList)
                    Update(p => p.Message = $"Defender 检出：{t}");
            }
            // 定向扫描后拉取真实检测记录
            await CollectDefenderDetectionsAsync(found, ct, startedAt.ToLocalTime(), runId);
            UpdateTiming(startedAt);
            Update(p => { });
        }
    }

    private async Task CollectDefenderDetectionsAsync(HashSet<string> found, CancellationToken ct,
        DateTime? since = null, Guid? runId = null)
    {
        try
        {
            var detections = await _defender.GetThreatDetectionsAsync(ct);
            foreach (var d in detections)
            {
                // 只归因于本次扫描期间（或之后）的检出，避免把历史记录算进本次结果
                if (since != null && d.DetectedAt < since.Value.AddSeconds(-5)) continue;
                PublishDetection(d, found, runId ?? CurrentProgress.RunId);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { AddWarning($"Defender 检测记录读取失败：{ex.Message}"); }
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

    public Task CancelAsync()
    {
        lock (_gate)
        {
            if (_cts == null || CurrentProgress.State is not (ScanState.Running or ScanState.Paused or ScanState.Preparing))
                return Task.CompletedTask;
            Update(p => { p.State = ScanState.Cancelling; p.Message = "正在取消扫描…"; });
            _cts.Cancel();
        }
        return Task.CompletedTask;
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
