using System.Collections.ObjectModel;
using System.IO;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Data.Repositories;
using PcSecurityCenter.App.Services;

namespace PcSecurityCenter.App.ViewModels;

/// <summary>病毒查杀页：三种扫描 + Defender 集成状态 + 威胁处理 + 隔离区。</summary>
public partial class ScanViewModel : ObservableObject
{
    private readonly IScanOrchestrator _scanner;
    private readonly IDefenderClient _defender;
    private readonly IQuarantineService _quarantine;
    private readonly ThreatRepository _threatRepo;
    private readonly ScanRunRepository _scanRepo;
    private readonly ISecurityEventService _events;
    private readonly IDialogService _dialogs;
    private readonly IConfigService _config;

    public ScanProgress Progress => _scanner.CurrentProgress;

    [NotifyCanExecuteChangedFor(nameof(PauseCommand), nameof(ResumeCommand), nameof(CancelCommand))]
    [ObservableProperty] private ScanState _scanState = ScanState.Idle;
    [ObservableProperty] private string _scanStateText = "空闲";
    [ObservableProperty] private string _scanMessage = "选择扫描类型开始检测。快速扫描约 1-5 分钟；全盘扫描耗时较长且支持暂停/继续/取消。";
    [ObservableProperty] private int _percent;
    [ObservableProperty] private long _filesScanned;
    [ObservableProperty] private long _filesTotal;
    [ObservableProperty] private string _speedText = "";
    [ObservableProperty] private string _currentItem = "";
    [ObservableProperty] private string _elapsedText = "";
    [ObservableProperty] private string _engineText = "…";
    [ObservableProperty] private string _signatureText = "…";
    [ObservableProperty] private bool _defenderAvailable;
    [ObservableProperty] private bool _isScanning;
    [ObservableProperty] private string _coverageWarnings = "";
    [ObservableProperty] private bool _isEstimating;
    [ObservableProperty] private string _threatSearch = "";
    [ObservableProperty] private bool _confirmedOnly;
    public ICollectionView ThreatsView { get; }
    public bool CanStartScan => !IsScanning;
    public string ThreatCountText => $"显示 {ThreatsView.Cast<object>().Count()} / 共 {Threats.Count} 条";
    partial void OnIsScanningChanged(bool value) => OnPropertyChanged(nameof(CanStartScan));
    partial void OnThreatSearchChanged(string value) => RefreshThreatFilter();
    partial void OnConfirmedOnlyChanged(bool value) => RefreshThreatFilter();
    private void RefreshThreatFilter()
    {
        ThreatsView.Refresh();
        OnPropertyChanged(nameof(ThreatCountText));
    }


    public ObservableCollection<ThreatInfo> Threats { get; } = new();
    public ObservableCollection<QuarantineEntry> QuarantineEntries { get; } = new();
    public ObservableCollection<string> CustomPaths { get; } = new();
    [ObservableProperty] private string _newPath = "";

    public ScanViewModel(IScanOrchestrator scanner, IDefenderClient defender, IQuarantineService quarantine,
        ThreatRepository threatRepo, ScanRunRepository scanRepo, ISecurityEventService events,
        IDialogService dialogs, IConfigService config)
    {
        _scanner = scanner;
        _defender = defender;
        _quarantine = quarantine;
        _threatRepo = threatRepo;
        _scanRepo = scanRepo;
        _events = events;
        _dialogs = dialogs;
        _config = config;
        ThreatsView = CollectionViewSource.GetDefaultView(Threats);
        ThreatsView.Filter = item => item is ThreatInfo t &&
            (!ConfirmedOnly || t.Kind == DetectionKind.Confirmed) &&
            (string.IsNullOrWhiteSpace(ThreatSearch) ||
             new[] { t.Name, t.FilePath, t.Engine, t.Evidence }.Any(v => v.Contains(ThreatSearch.Trim(), StringComparison.OrdinalIgnoreCase)));
        Threats.CollectionChanged += (_, _) => OnPropertyChanged(nameof(ThreatCountText));

        _scanner.ProgressChanged += (_, p) => Ui.Post(() => OnProgress(p));
        _scanner.ThreatFound += (_, t) =>
        {
            lock (_persistenceGate)
                _pendingWrites.Add(Task.Run(() => _threatRepo.Upsert(t)));
            Ui.Post(() => Threats.Insert(0, t));
        };
        _scanner.Completed += (_, p) => _completionTask = OnScanCompletedAsync(p);

        _ = LoadDefenderStatusAsync();
        _ = LoadThreatsAsync();
        _ = LoadQuarantineAsync();
    }

    private readonly object _persistenceGate = new();
    private readonly List<Task> _pendingWrites = new();
    private Task _completionTask = Task.CompletedTask;
    // 进度事件约 33 次/秒，全部写入绑定额外造成每秒上百次重排。
    // 这里按 150ms 节流（约 6-7 次/秒），扫描状态类字段仍然实时更新。
    private DateTime _lastProgressUi = DateTime.MinValue;
    private ScanProgress? _pendingProgress;

    private async Task LoadDefenderStatusAsync()
    {
        try
        {
            var st = await _defender.GetStatusAsync();
            DefenderAvailable = st.Installed && st.EngineAvailable;
            EngineText = st.Installed
                ? $"Microsoft Defender：{(st.EngineAvailable ? "引擎可用" : "引擎异常")}，实时防护 {(st.RealTimeProtection ? "开启" : "关闭")}"
                : "未检测到 Microsoft Defender —— 将仅使用智能风险规则引擎（病毒判定能力受限）";
            SignatureText = st.SignatureLastUpdated != null
                ? $"病毒库版本 {st.SignatureVersion}（更新于 {st.SignatureLastUpdated:yyyy-MM-dd HH:mm}）"
                : "无法读取病毒库信息";
        }
        catch (Exception ex)
        {
            EngineText = "Defender 状态读取失败：" + ex.Message;
        }
    }

    [RelayCommand]
    private async Task RefreshDefenderAsync()
    {
        await LoadDefenderStatusAsync();
        await _dialogs.InfoAsync("引擎状态", "已刷新 Defender 状态。");
    }

    [RelayCommand]
    private async Task UpdateSignaturesAsync()
    {
        ScanMessage = "正在更新病毒库（约 10-60 秒）…";
        var ok = await _defender.UpdateSignaturesAsync();
        ScanMessage = ok ? "病毒库已更新。" : "病毒库更新失败（详见日志）。";
        await LoadDefenderStatusAsync();
    }

    // ============ 扫描 ============
    [RelayCommand]
    private Task StartQuickAsync()
    {
        Serilog.Log.Information("UI: 用户点击开始快速扫描");
        return StartAsync(new ScanRequest { Type = ScanType.Quick });
    }

    [RelayCommand]
    private Task StartFullAsync() => StartAsync(new ScanRequest { Type = ScanType.Full });

    [RelayCommand]
    private async Task AddFolderAsync()
    {
        var dlg = new Microsoft.Win32.OpenFolderDialog { Title = "选择要扫描的文件夹" };
        if (dlg.ShowDialog() == true)
        {
            CustomPaths.Add(dlg.FolderName);
        }
        await Task.CompletedTask;
    }

    [RelayCommand]
    private async Task AddFileAsync()
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Title = "选择要扫描的文件" };
        if (dlg.ShowDialog() == true) CustomPaths.Add(dlg.FileName);
        await Task.CompletedTask;
    }

    [RelayCommand]
    private void RemovePath(object? param)
    {
        if (param is string p) CustomPaths.Remove(p);
    }

    [RelayCommand]
    private async Task StartCustomAsync()
    {
        if (CustomPaths.Count == 0)
        {
            await _dialogs.InfoAsync("自定义扫描", "请先添加至少一个文件或文件夹。");
            return;
        }
        await StartAsync(new ScanRequest { Type = ScanType.Custom, RootPaths = CustomPaths.ToList() });
    }

    private async Task StartAsync(ScanRequest request)
    {
        if (IsScanning) return;
        Threats.Clear();
        lock (_persistenceGate) _pendingWrites.Clear();
        _completionTask = Task.CompletedTask;
        _lastProgressUi = DateTime.MinValue;
        IsScanning = true;
        ScanStateText = "准备中";
        try
        {
            await _scanner.StartAsync(request);
            await _completionTask;
        }
        catch (Exception ex)
        {
            ScanMessage = "扫描启动失败：" + ex.Message;
        }
        finally { IsScanning = false; }
    }

    private bool CanPause() => ScanState == ScanState.Running;
    private bool CanResume() => ScanState == ScanState.Paused;
    private bool CanCancel() => ScanState is ScanState.Preparing or ScanState.Running or ScanState.Paused;

    [RelayCommand(CanExecute = nameof(CanPause))]
    private void Pause() => _scanner.Pause();

    [RelayCommand(CanExecute = nameof(CanResume))]
    private void Resume() => _scanner.Resume();

    [RelayCommand(CanExecute = nameof(CanCancel))]
    private async Task CancelAsync() => await _scanner.CancelAsync();

    private void OnProgress(ScanProgress p)
    {
        // 高频进度事件节流：状态/消息类字段立即更新，数值类字段按 150ms 合并刷新
        var isTerminal = p.State is ScanState.Completed or ScanState.Cancelled or ScanState.Failed;
        var now = DateTime.UtcNow;
        _pendingProgress = p;
        if (!isTerminal && p.State == ScanState && (now - _lastProgressUi).TotalMilliseconds < 150) return;
        _lastProgressUi = now;
        ApplyProgress(_pendingProgress);
    }

    private void ApplyProgress(ScanProgress p)
    {
        ScanState = p.State;
        ScanStateText = p.State switch
        {
            ScanState.Preparing => "准备中",
            ScanState.Running => "扫描中",
            ScanState.Paused => "已暂停",
            ScanState.Cancelling => "取消中",
            ScanState.Completed => string.IsNullOrEmpty(p.CoverageWarnings) ? "已完成" : "覆盖受限",
            ScanState.Cancelled => "已取消",
            ScanState.Failed => "失败",
            _ => "空闲",
        };
        ScanMessage = p.Message;
        CoverageWarnings = p.CoverageWarnings;
        IsEstimating = p.IsEstimating;
        Percent = p.Percent;
        FilesScanned = p.FilesScanned;
        FilesTotal = p.FilesTotal;
        CurrentItem = p.CurrentItem;
        SpeedText = p.FilesPerSecond > 0 ? $"{p.FilesPerSecond:F0} 文件/秒" : "";
        ElapsedText = p.Elapsed > TimeSpan.FromSeconds(0.5)
            ? $"{(int)p.Elapsed.TotalMinutes:00}:{p.Elapsed.Seconds:00}"
            : "";
        // 扫描结果与历史落库完成前保持操作锁，避免新扫描混入旧扫描收尾。
    }

    private async Task OnScanCompletedAsync(ScanProgress p)
    {
        try
        {
            Ui.Post(() => OnProgress(p));
            Task[] writes;
            lock (_persistenceGate) writes = _pendingWrites.ToArray();
            await Task.WhenAll(writes);
            // 记录扫描历史。Id 必须与本次扫描的 RunId 一致，
            // 否则威胁记录的 scan_run_id 永远匹配不到扫描记录（历史上正是如此）。
            var record = new ScanRunRecord
            {
                Id = p.RunId == Guid.Empty ? Guid.NewGuid() : p.RunId,
                Type = p.Type,
                StartedAt = DateTime.Now - p.Elapsed,
                FinishedAt = DateTime.Now,
                FinalState = p.State,
                FilesScanned = p.FilesScanned,
                ThreatsFound = p.ThreatsFound,
                Engines = p.EngineName,
                Scope = p.Scope,
                UncoveredNotes = p.CoverageWarnings + "\n文件计数为本工具枚举量，不代表 Defender 实际检测文件数；跳过不可访问路径与重解析点，不覆盖网络行为分析。",
            };
            await Task.Run(() => _scanRepo.Insert(record));
            if (p.State == ScanState.Completed && string.IsNullOrEmpty(p.CoverageWarnings) && p.Type == ScanType.Quick) _config.Current.LastQuickScanTime = DateTime.Now;
            if (p.State == ScanState.Completed && string.IsNullOrEmpty(p.CoverageWarnings) && p.Type == ScanType.Full) _config.Current.LastFullScanTime = DateTime.Now;
            if (!await _config.SaveAsync()) throw new IOException("扫描记录已保存，但配置保存失败。");

            await _events.PublishAsync(new SecurityEvent
            {
                Type = SecurityEventType.SystemCheck,
                Severity = p.ThreatsFound > 0 ? ThreatSeverity.Medium : ThreatSeverity.Info,
                Title = $"{ScanTypeName(p.Type)}：{p.State}",
                Detail = p.Message + "\n" + p.CoverageWarnings,
            });

        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "扫描结果保存失败");
            Ui.Post(() => ScanMessage = p.Message + " 结果保存失败：" + ex.Message);
        }
    }

    private static string ScanTypeName(ScanType t) => t switch
    {
        ScanType.Quick => "快速扫描", ScanType.Full => "全盘扫描", _ => "自定义扫描",
    };

    // ============ 威胁处理 ============
    [RelayCommand]
    private async Task QuarantineThreatAsync(object? param)
    {
        if (IsScanning) return; // 等待本次结果落库后才能修改处理状态。
        if (param is not ThreatInfo t) return;
        var danger = t.Engine == "MicrosoftDefender";
        if (danger)
        {
            await _dialogs.InfoAsync("请在 Windows 安全中心处理",
                "Defender 官方 Remove-MpThreat 只能处理全部活动威胁，不能按本条记录定点隔离。请打开 Windows 安全中心 → 病毒和威胁防护 → 保护历史记录，核对该文件后处理。\n\n" + t.FilePath);
            return;
        }

        var ok = await _dialogs.ConfirmAsync("隔离威胁",
            $"将隔离：{t.FilePath}\n\n该文件将移入本工具加密隔离区（AES-256），可恢复或彻底删除。",
            "执行隔离", danger: true);
        if (!ok) return;

        try
        {
            var entry = await _quarantine.QuarantineFileAsync(t.FilePath, t.Evidence, t.Engine, t.Severity);
            t.Status = ThreatStatus.Quarantined;
            _threatRepo.UpdateStatus(t.Id, ThreatStatus.Quarantined);
            QuarantineEntries.Insert(0, entry);
            await _dialogs.InfoAsync("威胁处理", $"已隔离到安全区：{entry.VaultFileName}");
            Threats.Remove(t);
        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "隔离失败 {Path}", t.FilePath);
            await _dialogs.InfoAsync("威胁处理", "隔离失败：" + ex.Message);
        }
    }

    [RelayCommand]
    private async Task AllowThreatAsync(object? param)
    {
        if (IsScanning) return; // 等待本次结果落库后才能修改处理状态。
        if (param is not ThreatInfo t) return;
        var ok = await _dialogs.ConfirmAsync("忽略本条记录",
            $"将忽略此风险：{t.FilePath}\n\n仅标记本条检测记录为已忽略；后续扫描仍会重新检查该文件，不修改 Defender 排除项。",
            "忽略", danger: true);
        if (!ok) return;
        t.Status = ThreatStatus.Ignored;
        _threatRepo.UpdateStatus(t.Id, ThreatStatus.Ignored);
        Threats.Remove(t);
    }

    [RelayCommand]
    private async Task DeleteThreatAsync(object? param)
    {
        if (IsScanning) return; // 等待本次结果落库后才能修改处理状态。
        if (param is not ThreatInfo t) return;
        var ok = await _dialogs.ConfirmAsync("永久删除文件",
            $"将永久删除：{t.FilePath}\n\n该操作不可恢复！推荐使用「隔离」保留恢复可能性。",
            "永久删除", danger: true);
        if (!ok) return;
        try
        {
            if (File.Exists(t.FilePath))
            {
                File.Delete(t.FilePath);
                t.Status = ThreatStatus.Removed;
                _threatRepo.UpdateStatus(t.Id, ThreatStatus.Removed);
                await _dialogs.InfoAsync("删除", "文件已删除。");
            }
            else
            {
                await _dialogs.InfoAsync("删除", "文件已不存在（可能已被其他程序处理）。");
                t.Status = ThreatStatus.Removed;
                _threatRepo.UpdateStatus(t.Id, ThreatStatus.Removed);
            }
            Threats.Remove(t);
        }
        catch (Exception ex)
        {
            await _dialogs.InfoAsync("删除", "删除失败：" + ex.Message);
        }
    }

    [RelayCommand]
    private async Task ShowThreatDetailAsync(object? param)
    {
        if (param is not ThreatInfo t) return;
        await _dialogs.InfoAsync(t.Name,
            $"风险等级：{t.Severity}\n类型：{t.Kind}\n文件位置：{t.FilePath}\n检测引擎：{t.Engine}\n" +
            $"检测依据：{t.Evidence}\n检测时间：{t.DetectedAt:yyyy-MM-dd HH:mm:ss}\n" +
            $"SHA256：{(string.IsNullOrEmpty(t.Sha256) ? "（不可用）" : t.Sha256)}\n处理建议：{t.Recommendation}\n当前状态：{t.Status}");
    }

    // ============ 隔离区 ============
    [RelayCommand]
    private async Task RestoreQuarantinedAsync(object? param)
    {
        if (param is not QuarantineEntry q) return;
        var ok = await _dialogs.ConfirmAsync("恢复隔离文件",
            $"将恢复：{q.OriginalPath}\n\n恢复后文件回到原位置。请确认该文件无害（隔离时原因：{q.Reason}）。",
            "恢复", danger: true);
        if (!ok) return;
        var r = await _quarantine.RestoreAsync(q.Id);
        await _dialogs.InfoAsync("恢复", r ? "文件已恢复到原位置。" : "恢复失败：完整性校验未通过或文件丢失（详见日志）。");
    }

    [RelayCommand]
    private async Task DeleteQuarantinedAsync(object? param)
    {
        if (param is not QuarantineEntry q) return;
        var ok = await _dialogs.ConfirmAsync("彻底删除隔离文件",
            $"将彻底删除隔离区中的：{q.FileName}\n\n密文将被安全覆写，无法恢复。",
            "彻底删除", danger: true);
        if (!ok) return;
        var r = await _quarantine.DeleteAsync(q.Id);
        if (r) QuarantineEntries.Remove(q);
        await _dialogs.InfoAsync("删除", r ? "已彻底删除。" : "删除失败。");
    }

    [RelayCommand]
    private async Task OpenVaultLocationAsync()
    {
        try { System.Diagnostics.Process.Start("explorer.exe", _quarantine.VaultDirectory); } catch (Exception) { }
        await Task.CompletedTask;
    }

    private async Task LoadThreatsAsync()
    {
        try
        {
            foreach (var t in _threatRepo.GetRecent(100).Where(x => x.Status == ThreatStatus.Active).OrderByDescending(x => x.DetectedAt).Take(50))
                Threats.Add(t);
        }
        catch (Exception) { }
        await Task.CompletedTask;
    }

    private async Task LoadQuarantineAsync()
    {
        try
        {
            foreach (var q in await _quarantine.ListAsync()) QuarantineEntries.Add(q);
        }
        catch (Exception) { }
        await Task.CompletedTask;
    }
}
