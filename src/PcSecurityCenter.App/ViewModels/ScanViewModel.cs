using System.Collections.ObjectModel;
using System.IO;
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

        _scanner.ProgressChanged += (_, p) => Ui.Post(() => OnProgress(p));
        _scanner.ThreatFound += (_, t) =>
        {
            if (!_seenThreats.Add(t.FilePath + "|" + t.Name)) return; // HashSet 查重：避免 O(n²)
            Ui.Post(() =>
            {
                Threats.Insert(0, t);
                _ = Task.Run(() => _threatRepo.Upsert(t)); // 写库离线程，不占 UI
            });
        };
        _scanner.Completed += async (_, p) => await OnScanCompletedAsync(p);

        _ = LoadDefenderStatusAsync();
        _ = LoadThreatsAsync();
        _ = LoadQuarantineAsync();
    }

    private readonly HashSet<string> _seenThreats = new(StringComparer.OrdinalIgnoreCase);
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
        IsScanning = true;
        ScanStateText = "准备中";
        try
        {
            await _scanner.StartAsync(request);
        }
        catch (Exception ex)
        {
            ScanMessage = "扫描启动失败：" + ex.Message;
            IsScanning = false;
        }
    }

    [RelayCommand]
    private void Pause() => _scanner.Pause();

    [RelayCommand]
    private void Resume() => _scanner.Resume();

    [RelayCommand]
    private async Task CancelAsync() => await _scanner.CancelAsync();

    private void OnProgress(ScanProgress p)
    {
        // 高频进度事件节流：状态/消息类字段立即更新，数值类字段按 150ms 合并刷新
        var isTerminal = p.State is ScanState.Completed or ScanState.Cancelled or ScanState.Failed;
        var now = DateTime.UtcNow;
        _pendingProgress = p;
        if (!isTerminal && (now - _lastProgressUi).TotalMilliseconds < 150) return;
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
            ScanState.Completed => "已完成",
            ScanState.Cancelled => "已取消",
            ScanState.Failed => "失败",
            _ => "空闲",
        };
        ScanMessage = p.Message;
        Percent = p.Percent;
        FilesScanned = p.FilesScanned;
        FilesTotal = p.FilesTotal;
        CurrentItem = p.CurrentItem;
        SpeedText = p.FilesPerSecond > 0 ? $"{p.FilesPerSecond:F0} 文件/秒" : "";
        ElapsedText = p.Elapsed > TimeSpan.FromSeconds(0.5)
            ? $"{(int)p.Elapsed.TotalMinutes:00}:{p.Elapsed.Seconds:00}"
            : "";
        IsScanning = p.State is ScanState.Running or ScanState.Preparing or ScanState.Paused or ScanState.Cancelling;
    }

    private async Task OnScanCompletedAsync(ScanProgress p)
    {
        Ui.Post(() =>
        {
            IsScanning = false;
            OnProgress(p);
        });

        // 记录扫描历史
        var record = new ScanRunRecord
        {
            Type = p.Type,
            StartedAt = DateTime.Now - p.Elapsed,
            FinishedAt = DateTime.Now,
            FinalState = p.State,
            FilesScanned = p.FilesScanned,
            ThreatsFound = p.ThreatsFound,
            Engines = p.EngineName,
            Scope = p.Message,
            UncoveredNotes = "扫描未包含内存驻留检测与网络行为分析；Defender 原生快速扫描覆盖系统内存与启动区域。",
        };
        _scanRepo.Insert(record);
        if (p.Type == ScanType.Quick) _config.Current.LastQuickScanTime = DateTime.Now;
        if (p.Type == ScanType.Full) _config.Current.LastFullScanTime = DateTime.Now;
        await _config.SaveAsync();

        await _events.PublishAsync(new SecurityEvent
        {
            Type = SecurityEventType.SystemCheck,
            Severity = p.ThreatsFound > 0 ? ThreatSeverity.Medium : ThreatSeverity.Info,
            Title = $"{ScanTypeName(p.Type)}完成",
            Detail = $"检查 {p.FilesScanned} 个文件，发现 {p.ThreatsFound} 项风险。",
        });

        // 扫描后拉取 Defender 官方威胁记录（含原生扫描结果）
        try
        {
            var dets = await _defender.GetThreatDetectionsAsync();
            foreach (var d in dets)
                if (!Threats.Any(x => x.FilePath == d.FilePath && x.Engine == d.Engine))
                {
                    d.ScanRunId = null;
                    Threats.Insert(0, d);
                    _threatRepo.Upsert(d);
                }
        }
        catch (Exception) { }
    }

    private static string ScanTypeName(ScanType t) => t switch
    {
        ScanType.Quick => "快速扫描", ScanType.Full => "全盘扫描", _ => "自定义扫描",
    };

    // ============ 威胁处理 ============
    [RelayCommand]
    private async Task QuarantineThreatAsync(object? param)
    {
        if (param is not ThreatInfo t) return;
        var danger = t.Engine == "MicrosoftDefender";
        var ok = await _dialogs.ConfirmAsync("隔离威胁",
            $"将隔离：{t.FilePath}\n\n" + (danger
                ? "该威胁由 Microsoft Defender 检出，将通过 Defender 官方接口（Remove-MpThreat）执行隔离/清除。"
                : "该文件将移入本工具加密隔离区（AES-256），可随时恢复或彻底删除。"),
            "执行隔离", danger: true);
        if (!ok) return;

        try
        {
            if (danger)
            {
                var r = await _defender.RemoveThreatsAsync();
                if (r)
                {
                    t.Status = ThreatStatus.Quarantined;
                    _threatRepo.UpdateStatus(t.Id, ThreatStatus.Quarantined);
                    await _dialogs.InfoAsync("威胁处理", "已通过 Defender 官方接口清除活动威胁。");
                }
                else
                {
                    await _dialogs.InfoAsync("威胁处理", "Defender 清除失败：威胁可能已被系统处理，或需要管理员权限。可打开 Windows 安全中心查看。");
                }
            }
            else
            {
                var entry = await _quarantine.QuarantineFileAsync(t.FilePath, t.Evidence, t.Engine, t.Severity);
                t.Status = ThreatStatus.Quarantined;
                _threatRepo.UpdateStatus(t.Id, ThreatStatus.Quarantined);
                QuarantineEntries.Insert(0, entry);
                await _dialogs.InfoAsync("威胁处理", $"已隔离到安全区：{entry.VaultFileName}");
            }
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
        if (param is not ThreatInfo t) return;
        var ok = await _dialogs.ConfirmAsync("加入白名单/忽略",
            $"将忽略此风险：{t.FilePath}\n\n加入白名单后本工具不再提示该项（不影响 Defender 实时防护对它的检测）。",
            "忽略", danger: true);
        if (!ok) return;
        t.Status = ThreatStatus.Allowed;
        _threatRepo.UpdateStatus(t.Id, ThreatStatus.Allowed);
        Threats.Remove(t);
    }

    [RelayCommand]
    private async Task DeleteThreatAsync(object? param)
    {
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
