using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Data.Repositories;
using PcSecurityCenter.App.Services;

namespace PcSecurityCenter.App.ViewModels;

/// <summary>驾驶舱：综合评分 + 全部状态卡来自真实检查与真实硬件数据。</summary>
public partial class DashboardViewModel : ObservableObject, IPageActivatable
{
    private readonly ISecurityCheckService _checks;
    private readonly IDefenderClient _defender;
    private readonly IPerformanceMonitor _performance;
    private readonly INetworkMonitor _network;
    private readonly ISecurityEventService _events;
    private readonly IScanOrchestrator _scanner;
    private readonly NavigationService _navigation;
    private readonly IConfigService _config;
    private readonly CheckResultRepository _checkRepo;
    private readonly ThreatRepository _threatRepo;
    private readonly IDialogService _dialogs;

    [ObservableProperty] private int _score;
    [ObservableProperty] private string _scoreGrade = "—";
    [ObservableProperty] private string _scoreSummary = "点击「一键全面体检」获取真实安全评分";
    [ObservableProperty] private string _globalStateText = "评估中";
    [ObservableProperty] private bool _isChecking;
    [ObservableProperty] private string _lastCheckText = "从未检查";

    // 防护状态卡
    [ObservableProperty] private string _defenderStatus = "…";
    [ObservableProperty] private string _firewallStatus = "…";
    [ObservableProperty] private string _updateStatus = "…";
    [ObservableProperty] private string _threatCountText = "…";
    [ObservableProperty] private string _lastScanText = "从未扫描";

    // 硬件（真实采样）
    [ObservableProperty] private string _cpuText = "…";
    [ObservableProperty] private double _cpuPercent;
    [ObservableProperty] private string _memoryText = "…";
    [ObservableProperty] private double _memoryPercent;
    [ObservableProperty] private string _diskText = "…";
    [ObservableProperty] private double _diskPercent;
    [ObservableProperty] private string _gpuText = "…";
    [ObservableProperty] private double _gpuPercent;
    [ObservableProperty] private string _netSpeedText = "…";
    [ObservableProperty] private string _cpuName = "";
    [ObservableProperty] private string _osName = "";

    public ObservableCollection<SecurityEvent> RecentEvents { get; } = new();
    public ObservableCollection<string> RepairSuggestions { get; } = new();

    public DashboardViewModel(ISecurityCheckService checks, IDefenderClient defender, IPerformanceMonitor performance,
        INetworkMonitor network, ISecurityEventService events, IScanOrchestrator scanner, NavigationService navigation,
        IConfigService config, CheckResultRepository checkRepo, ThreatRepository threatRepo, IDialogService dialogs)
    {
        _checks = checks;
        _defender = defender;
        _performance = performance;
        _network = network;
        _events = events;
        _scanner = scanner;
        _navigation = navigation;
        _config = config;
        _checkRepo = checkRepo;
        _threatRepo = threatRepo;
        _dialogs = dialogs;

        // 性能实时刷新（窗口最小化或离开本页时跳过，减少无谓排版开销）
        _performance.Sampled += (_, snap) =>
        {
            if (!_isActive) return;
            // 采样回调在计时器线程：这里不能读 WindowState（WPF 对象有线程亲和性，
            // 跨线程访问会抛 InvalidOperationException 并被计时器吞掉，导致卡片永远停在「…」）。
            Ui.Post(() =>
            {
                if (!IsWindowMinimized()) UpdatePerformance(snap);
            });
        };
        _performance.Start();
        _ = LoadLastCheckAsync();
        _ = LoadRecentEventsAsync();
        _ = LoadLastScanTextAsync();
        _ = LoadOsAsync(); // 启动时一次性加载，采样循环里不再重复触发
    }

    private static bool IsWindowMinimized() =>
        Application.Current?.MainWindow is { } w && w.WindowState == WindowState.Minimized;

    // 离开驾驶舱页时暂停性能 UI 刷新（采样由采集器统一管理）
    public void OnPageActivated()
    {
        _isActive = true;
        _ = RefreshPerformanceAsync();
    }

    public void OnPageDeactivated() => _isActive = false;
    private bool _isActive = true;

    [RelayCommand]
    private async Task FullCheckAsync()
    {
        if (IsChecking) return;
        IsChecking = true;
        ScoreSummary = "正在执行系统安全检查（含在线更新查询，约 30-90 秒）…";
        try
        {
            var items = await _checks.RunAllChecksAsync();
            var score = _checks.CalculateScore(items);
            Score = score.Total;
            ScoreGrade = score.Grade;
            ScoreSummary = score.Summary;

            // 落库（线程池执行，不阻塞 UI）
            var runId = Guid.NewGuid().ToString("N");
            await Task.Run(() => _checkRepo.InsertBatch(runId, items));
            _config.Current.LastHealthCheckTime = DateTime.Now;
            _config.Current.LastSecurityScore = score.Total;
            await _config.SaveAsync();

            // 状态卡
            foreach (var c in items)
            {
                switch (c.Id)
                {
                    case "defender-engine": DefenderStatus = c.Result; break;
                    case "wupending": UpdateStatus = c.Result; break;
                    case "active-threats": ThreatCountText = c.Result; break;
                }
                if (c.Id.StartsWith("firewall") && c.Id.EndsWith("domain")) FirewallStatus = c.Result;
                else if (c.Id == "firewall" || FirewallStatus == "…" && c.Id.StartsWith("firewall")) FirewallStatus = c.Result;
            }

            // 修复建议
            RepairSuggestions.Clear();
            foreach (var c in items.Where(x => x.Status is CheckStatus.Risk or CheckStatus.Warning && !string.IsNullOrEmpty(x.Recommendation)).Take(8))
                RepairSuggestions.Add($"[{c.Name}] {c.Recommendation}");
            if (RepairSuggestions.Count == 0) RepairSuggestions.Add("未发现需要处理的风险项。");

            var worst = items.Any(x => x.Status == CheckStatus.Risk);
            GlobalStateText = worst ? "存在风险" : score.Total >= 75 ? "状态良好" : "需要关注";
            LastCheckText = $"最近检查：{DateTime.Now:yyyy-MM-dd HH:mm}";
            await _events.PublishAsync(new SecurityEvent
            {
                Type = SecurityEventType.SystemCheck,
                Severity = worst ? ThreatSeverity.Medium : ThreatSeverity.Info,
                Title = "系统安全检查完成",
                Detail = $"评分 {score.Total}（{score.Grade}），共 {items.Count} 项检查。",
            });
            await LoadRecentEventsAsync();
        }
        catch (Exception ex)
        {
            ScoreSummary = "检查失败：" + ex.Message;
            Serilog.Log.Error(ex, "全面体检失败");
        }
        finally { IsChecking = false; }
    }

    [RelayCommand]
    private void QuickScan()
    {
        _navigation.Navigate(PageKind.Scan);
    }

    [RelayCommand]
    private async Task RefreshPerformanceAsync()
    {
        try
        {
            var snap = await _performance.SampleAsync();
            UpdatePerformance(snap);
            var net = await _network.GetTotalTrafficSampleAsync();
            NetSpeedText = $"↓ {FormatSpeed(net.DownloadBytesPerSec)}  ↑ {FormatSpeed(net.UploadBytesPerSec)}";
        }
        catch (Exception) { }
    }

    [RelayCommand]
    private async Task UpdateSignaturesAsync()
    {
        await _dialogs.InfoAsync("更新病毒库", "正在通过 Microsoft Update 服务器更新 Defender 病毒库，完成后会自动提示。");
        var ok = await _defender.UpdateSignaturesAsync();
        await _dialogs.InfoAsync("更新病毒库", ok ? "病毒库更新完成。" : "病毒库更新失败，请检查网络或稍后重试（详见日志）。");
    }

    private void UpdatePerformance(PerformanceSnapshot snap)
    {
        CpuPercent = snap.Cpu.UsagePercent;
        CpuText = $"CPU {snap.Cpu.UsagePercent:F0}%（{snap.Cpu.LogicalCores} 逻辑核心）";
        if (!string.IsNullOrEmpty(snap.Cpu.Name) && string.IsNullOrEmpty(CpuName)) CpuName = snap.Cpu.Name;
        MemoryPercent = snap.Memory.UsagePercent;
        MemoryText = $"内存 {snap.Memory.UsagePercent:F0}%（已用 {PcSecurityCenter.Core.Utils.SizeFormat.Format((long)snap.Memory.UsedBytes)} / {PcSecurityCenter.Core.Utils.SizeFormat.Format((long)snap.Memory.TotalBytes)}）";
        if (snap.Disks.Count > 0)
        {
            DiskPercent = snap.Disks[0].UsedPercent;
            DiskText = $"系统盘已用 {snap.Disks[0].UsedPercent:F0}%（剩余 {PcSecurityCenter.Core.Utils.SizeFormat.Format((long)snap.Disks[0].FreeBytes)}）";
        }
        if (snap.Gpu.UsagePercent != null)
        {
            GpuPercent = snap.Gpu.UsagePercent.Value;
            GpuText = $"GPU {snap.Gpu.UsagePercent.Value:F0}%（{snap.Gpu.Name}）";
        }
        else
        {
            GpuText = $"GPU 利用率不可用（{snap.Gpu.Name}）";
        }
        double dl = 0, up = 0;
        foreach (var n in snap.Networks) { dl += n.DownloadBytesPerSec; up += n.UploadBytesPerSec; }
        if (dl + up > 0) NetSpeedText = $"↓ {FormatSpeed(dl)}  ↑ {FormatSpeed(up)}";
    }

    private async Task LoadOsAsync()
    {
        try
        {
            var hw = await _performance.GetHardwareInfoAsync();
            OsName = $"{hw.OsName}（Build {hw.OsBuild}）";
            CpuName = hw.CpuName;
        }
        catch (Exception) { }
    }

    private async Task LoadLastCheckAsync()
    {
        var t = _config.Current.LastHealthCheckTime;
        if (t != default)
        {
            LastCheckText = $"最近检查：{t:yyyy-MM-dd HH:mm}";
            if (_config.Current.LastSecurityScore >= 0)
            {
                Score = _config.Current.LastSecurityScore;
                ScoreGrade = Score switch { >= 90 => "优秀", >= 75 => "良好", >= 60 => "一般", >= 40 => "较差", _ => "危险" };
                ScoreSummary = "上次体检结果；点击「一键全面体检」重新评估。";
            }
        }
        await Task.CompletedTask;
    }

    private async Task LoadRecentEventsAsync()
    {
        try
        {
            var events = await _events.GetRecentAsync(12);
            RecentEvents.Clear();
            foreach (var e in events) RecentEvents.Add(e);
        }
        catch (Exception) { }
    }

    private async Task LoadLastScanTextAsync()
    {
        var cfg = _config.Current;
        var last = cfg.LastFullScanTime != default ? cfg.LastFullScanTime : cfg.LastQuickScanTime;
        LastScanText = last != default ? $"最近扫描：{last:yyyy-MM-dd HH:mm}" : "从未扫描";
        await Task.CompletedTask;
    }

    private static string FormatSpeed(double bytesPerSec) => bytesPerSec switch
    {
        >= 1024 * 1024 => $"{bytesPerSec / 1024 / 1024:F1} MB/s",
        >= 1024 => $"{bytesPerSec / 1024:F0} KB/s",
        _ => $"{bytesPerSec:F0} B/s",
    };
}
