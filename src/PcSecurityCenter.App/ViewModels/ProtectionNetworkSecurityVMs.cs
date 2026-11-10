using System.Collections.ObjectModel;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Data.Repositories;
using PcSecurityCenter.App.Services;

namespace PcSecurityCenter.App.ViewModels;

/// <summary>实时防护页。</summary>
public partial class ProtectionViewModel : ObservableObject
{
    private readonly IRealtimeProtector _protector;
    private readonly IDefenderClient _defender;
    private readonly IConfigService _config;
    private readonly IDialogService _dialogs;

    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private string _defenderRtText = "…";
    [ObservableProperty] private string _watcherText = "…";
    [ObservableProperty] private string _pollText = "…";
    [ObservableProperty] private int _pollIntervalSec;

    public ObservableCollection<SecurityEvent> Events { get; } = new();

    public ProtectionViewModel(IRealtimeProtector protector, IDefenderClient defender,
        IConfigService config, ISecurityEventService events, IDialogService dialogs)
    {
        _protector = protector;
        _defender = defender;
        _config = config;
        _dialogs = dialogs;
        PollIntervalSec = config.Current.RealtimePollIntervalSec;
        IsRunning = protector.IsRunning;
        _protector.EventRaised += (_, e) => Ui.Post(() => { Events.Insert(0, e); TrimEvents(); });
        foreach (var e in protector.RecentEvents) Events.Add(e);
        _ = events.GetRecentAsync(30).ContinueWith(t =>
        {
            if (t.Result.Count > 0)
                Ui.Post(() =>
                {
                    foreach (var e in t.Result.Where(x => Events.All(y => y.Id != x.Id)))
                        Events.Add(e);
                    TrimEvents();
                });
        });
        _ = LoadDefenderAsync();
    }

    private void TrimEvents()
    {
        while (Events.Count > 100) Events.RemoveAt(Events.Count - 1);
    }

    private async Task LoadDefenderAsync()
    {
        var st = await _defender.GetStatusAsync();
        DefenderRtText = st.Installed
            ? $"实时防护 {(st.RealTimeProtection ? "开启" : "关闭")}；行为监控 {(st.BehaviorMonitor ? "开启" : "关闭")}"
            : "Defender 不可用";
    }

    [RelayCommand]
    private void ToggleProtection()
    {
        if (IsRunning)
        {
            _protector.Stop();
            IsRunning = false;
            _config.Current.RealtimeEnabled = false;
        }
        else
        {
            _protector.Start();
            IsRunning = true;
            _config.Current.RealtimeEnabled = true;
        }
        _ = _config.SaveAsync();
    }

    [RelayCommand]
    private async Task ApplyIntervalAsync()
    {
        var r = await _dialogs.PromptAsync("轮询间隔",
            "设置实时防护的低频轮询间隔（秒，5-300）。事件驱动的启动目录监控不受影响。", PollIntervalSec.ToString());
        if (!r.ok) return;
        if (int.TryParse(r.input, out var sec) && sec is >= 5 and <= 300)
        {
            PollIntervalSec = sec;
            _config.Current.RealtimePollIntervalSec = sec;
            await _config.SaveAsync();
            if (IsRunning) { _protector.Stop(); _protector.Start(); }
        }
        else
        {
            await _dialogs.InfoAsync("轮询间隔", "请输入 5-300 之间的整数。");
        }
    }

    [RelayCommand]
    private async Task ClearEventsAsync()
    {
        Events.Clear();
        await Task.CompletedTask;
    }
}

/// <summary>网络安全页。</summary>
public partial class NetworkViewModel : ObservableObject, IPageActivatable
{
    private readonly INetworkMonitor _network;
    private readonly IDialogService _dialogs;
    private readonly INotificationService _notifications;
    private System.Timers.Timer? _trafficTimer;
    // 会话内记住上次代理状态：仅在状态变化时提示，避免常开代理的用户每次进页都被弹窗打扰
    private string? _lastProxyKey;

    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string _trafficText = "…";
    [ObservableProperty] private string _proxyText = "…";
    [ObservableProperty] private string _hostsSummary = "…";
    [ObservableProperty] private string _dnsText = "…";
    [ObservableProperty] private string _hostsRaw = "";

    public ObservableCollection<NetworkAdapterInfo> Adapters { get; } = new();
    public ObservableCollection<TcpConnectionInfo> Connections { get; } = new();
    public ObservableCollection<FirewallProfileInfo> FirewallProfiles { get; } = new();
    public ObservableCollection<string> NonLocalHostsRedirects { get; } = new();

    public NetworkViewModel(INetworkMonitor network, IDialogService dialogs, INotificationService notifications)
    {
        _network = network;
        _dialogs = dialogs;
        _notifications = notifications;
        // 流量定时器：默认不启动；离开本页即停，避免后台空转消耗 CPU
        _trafficTimer = new System.Timers.Timer(2000) { AutoReset = true };
        _trafficTimer.Elapsed += (_, _) => _ = UpdateTrafficAsync();
        _ = LoadAsync();
    }

    // 页面激活/离开时由 NavigationService 调用（见 IPageActivatable）
    public void OnPageActivated() => _trafficTimer?.Start();
    public void OnPageDeactivated() => _trafficTimer?.Stop();

    private async Task UpdateTrafficAsync()
    {
        try
        {
            var t = await _network.GetTotalTrafficSampleAsync();
            // 采样回调在计时器线程：不能直接读 WindowState（WPF 对象有线程亲和性，
            // 跨线程访问会抛异常并被吞掉，网速文本将永远不更新）。
            Ui.Post(() =>
            {
                if (Application.Current?.MainWindow is { } w && w.WindowState == WindowState.Minimized) return;
                TrafficText =
                    $"↓ {PcSecurityCenter.Core.Utils.SizeFormat.Format((long)t.DownloadBytesPerSec)}/s   ↑ {PcSecurityCenter.Core.Utils.SizeFormat.Format((long)t.UploadBytesPerSec)}/s";
            });
        }
        catch (Exception) { }
    }

    [RelayCommand]
    private async Task RefreshAsync() => await LoadAsync();

    private async Task LoadAsync()
    {
        IsLoading = true;
        try
        {
            var adapters = await _network.GetAdaptersAsync();
            Ui.Post(() => { Adapters.Clear(); foreach (var a in adapters) Adapters.Add(a); });

            var conns = await _network.GetTcpConnectionsAsync();
            Ui.Post(() => { Connections.Clear(); foreach (var c in conns.Take(300)) Connections.Add(c); });

            var fw = await _network.GetFirewallProfilesAsync();
            Ui.Post(() => { FirewallProfiles.Clear(); foreach (var f in fw) FirewallProfiles.Add(f); });

            var proxy = await _network.GetProxyAsync();
            ProxyText = proxy.ProxyEnabled
                // 例外列表原本是一长串无空格字符，WPF 无法断行会横向溢出卡片；
                // 分号后添加空格让 WPF 按卡片宽度自然折行，避免每项都单独占一行。
                ? $"已启用系统代理：{proxy.ProxyServer}" +
                  (string.IsNullOrWhiteSpace(proxy.ProxyOverride)
                      ? ""
                      : $"{Environment.NewLine}例外：{proxy.ProxyOverride.Replace(";", "; ")}") +
                  $"{Environment.NewLine}若非本人设置，请立即检查！"
                : "未启用系统代理";
            // 不再用模态弹窗提醒代理状态（常开代理的用户每次进页都会被打断）；
            // 代理信息已在上图卡片常驻展示，这里只在状态发生变化时给一条可自动消失的 Toast。
            var proxyKey = proxy.ProxyEnabled ? proxy.ProxyServer : "";
            if (_lastProxyKey is { } prev && proxyKey != prev)
            {
                var before = prev.Length == 0 ? "未启用" : prev;
                var after = proxyKey.Length == 0 ? "未启用" : proxy.ProxyServer;
                _notifications.Notify("系统代理变更",
                    $"检测到系统代理变更：{before} → {after}。若非本人操作，请到 设置→网络→代理 关闭并排查。",
                    ThreatSeverity.Medium);
            }
            _lastProxyKey = proxyKey;

            var hosts = await _network.InspectHostsFileAsync();
            Ui.Post(() =>
            {
                HostsSummary = hosts.FileLockedByOther
                    ? "Hosts 文件读取受限（权限不足或被锁定）"
                    : $"共 {hosts.TotalEntries} 条有效条目；非本机回环重定向 {hosts.NonLocalRedirects.Count} 条";
                HostsRaw = hosts.RawContent;
                NonLocalHostsRedirects.Clear();
                foreach (var r in hosts.NonLocalRedirects) NonLocalHostsRedirects.Add(r);
            });

            var dns = await _network.GetDnsServersAsync();
            DnsText = dns.Count > 0 ? string.Join("、", dns) : "未读取到 DNS 配置";
        }
        catch (Exception ex)
        {
            Serilog.Log.Error(ex, "网络信息加载失败");
        }
        finally { IsLoading = false; }
    }

    [RelayCommand]
    private async Task FlushDnsAsync()
    {
        var ok = await _dialogs.ConfirmAsync("刷新 DNS 缓存", "将执行 ipconfig /flushdns 清空本机 DNS 缓存。该操作无风险且立即生效。");
        if (!ok) return;
        await _network.FlushDnsAsync();
        await _dialogs.InfoAsync("刷新 DNS", "DNS 缓存已刷新。");
    }
}

/// <summary>系统安全检查页。</summary>
public partial class SystemSecurityViewModel : ObservableObject
{
    private readonly ISecurityCheckService _checks;
    private readonly IPermissionService _permission;
    private readonly CheckResultRepository _checkRepo;
    private readonly ISecurityEventService _events;

    [ObservableProperty] private bool _isChecking;
    [ObservableProperty] private string _statusText = "尚未检查。点击「开始检查」运行全部安全检查。";
    [ObservableProperty] private int _score;
    [ObservableProperty] private string _grade = "";
    [ObservableProperty] private string _elevationHint;

    public ObservableCollection<SecurityCheckItem> Items { get; } = new();

    public SystemSecurityViewModel(ISecurityCheckService checks, IPermissionService permission,
        CheckResultRepository checkRepo, ISecurityEventService events)
    {
        _checks = checks;
        _permission = permission;
        _checkRepo = checkRepo;
        _events = events;
        _elevationHint = permission.ElevationHint;
        // 加载上次结果
        foreach (var item in _checkRepo.GetLatestRun()) Items.Add(item);
        if (Items.Count > 0) StatusText = $"显示上次检查结果（{Items.Count} 项），点击「开始检查」重新评估。";
    }

    [RelayCommand]
    private async Task RunChecksAsync()
    {
        if (IsChecking) return;
        IsChecking = true;
        StatusText = "正在检查（Windows 更新在线查询可能需要 1-2 分钟）…";
        Items.Clear();
        try
        {
            var results = await _checks.RunAllChecksAsync();
            foreach (var r in results) Items.Add(r);
            var score = _checks.CalculateScore(results);
            Score = score.Total;
            Grade = $"评分 {score.Total}（{score.Grade}）";
            StatusText = $"检查完成：{results.Count} 项。{score.Summary}";
            _checkRepo.InsertBatch(Guid.NewGuid().ToString("N"), results);
            await _events.PublishAsync(new SecurityEvent
            {
                Type = SecurityEventType.SystemCheck,
                Severity = results.Any(x => x.Status == CheckStatus.Risk) ? ThreatSeverity.Medium : ThreatSeverity.Info,
                Title = "系统安全检查完成",
                Detail = Grade,
            });
        }
        catch (Exception ex)
        {
            StatusText = "检查失败：" + ex.Message;
            Serilog.Log.Error(ex, "安全检查失败");
        }
        finally { IsChecking = false; }
    }
}

/// <summary>性能监控页（LiveCharts2 曲线 + 真实硬件数据）。</summary>
public partial class PerformanceViewModel : ObservableObject, IPageActivatable
{
    private readonly IPerformanceMonitor _monitor;
    private readonly IConfigService _config;

    [ObservableProperty] private string _cpuName = "";
    [ObservableProperty] private string _cpuCoresText = "";
    [ObservableProperty] private double _cpuUsage;
    [ObservableProperty] private double _memoryUsagePercent;
    [ObservableProperty] private string _memoryDetail = "";
    [ObservableProperty] private double _gpuUsage;
    [ObservableProperty] private string _gpuDetail = "";
    [ObservableProperty] private string _temperatureText = "暂不支持（本机未开放温度传感器读取）";
    [ObservableProperty] private string _netSpeedText = "";
    [ObservableProperty] private int _intervalMs;

    public ObservableCollection<DiskInfo> Disks { get; } = new();
    public ObservableCollection<double> CpuSeries { get; } = new();
    public ObservableCollection<double> MemSeries { get; } = new();
    public ObservableCollection<double> NetDownSeries { get; } = new();
    public ObservableCollection<double> NetUpSeries { get; } = new();
    public const int MaxPoints = 60;

    public ISeries[] CpuChartSeries { get; }
    public ISeries[] MemChartSeries { get; }
    public Axis[] YAxes { get; } = [new Axis { MinLimit = 0, MaxLimit = 100, LabelsPaint = null }];
    public Axis[] XAxes { get; } = [new Axis { LabelsPaint = null, IsVisible = false }];

    public PerformanceViewModel(IPerformanceMonitor monitor, IConfigService config)
    {
        _monitor = monitor;
        _config = config;
        IntervalMs = config.Current.PerformanceIntervalMs;

        var cpuPaint = new SolidColorPaint(new SkiaSharp.SKColor(0x22, 0xD3, 0xEE));
        var memPaint = new SolidColorPaint(new SkiaSharp.SKColor(0x3B, 0x82, 0xF6));
        CpuChartSeries =
        [
            new LineSeries<double>
            {
                Name = "CPU %",
                Values = CpuSeries,
                GeometrySize = 0,
                Stroke = cpuPaint,
                Fill = null,
                LineSmoothness = 0.35,
            },
        ];
        MemChartSeries =
        [
            new LineSeries<double>
            {
                Name = "内存 %",
                Values = MemSeries,
                GeometrySize = 0,
                Stroke = memPaint,
                Fill = null,
                LineSmoothness = 0.35,
            },
        ];

        _monitor.Sampled += (_, snap) =>
        {
            if (_isActive) Ui.Post(() => Update(snap));
        };
        if (!_monitor.IsRunning) _monitor.Start();
        _ = LoadStaticAsync();
    }

    private bool _isActive;

    public void OnPageActivated() => _isActive = true;
    public void OnPageDeactivated() => _isActive = false;

    private async Task LoadStaticAsync()
    {
        try
        {
            var hw = await _monitor.GetHardwareInfoAsync();
            CpuName = hw.CpuName;
            var snap = await _monitor.SampleAsync();
            CpuCoresText = $"{snap.Cpu.LogicalCores} 逻辑核心 / {hw.OsName}";
            Disks.Clear();
            foreach (var d in hw.Disks) Disks.Add(d);
        }
        catch (Exception) { }
    }

    private void Update(PerformanceSnapshot snap)
    {
        CpuUsage = snap.Cpu.UsagePercent;
        MemoryUsagePercent = snap.Memory.UsagePercent;
        MemoryDetail = $"{PcSecurityCenter.Core.Utils.SizeFormat.Format((long)snap.Memory.UsedBytes)} / {PcSecurityCenter.Core.Utils.SizeFormat.Format((long)snap.Memory.TotalBytes)}";
        GpuUsage = snap.Gpu.UsagePercent ?? 0;
        GpuDetail = snap.Gpu.UsagePercent != null
            ? $"{snap.Gpu.Name}（{snap.Gpu.Source}）"
            : $"{snap.Gpu.Name} —— 本机未提供 GPU 利用率计数器，不显示虚构数据";
        if (snap.Cpu.TemperatureC != null)
            TemperatureText = $"{snap.Cpu.TemperatureC:F0} °C（WMI MSAcpi_ThermalZoneTemperature）";

        double dl = 0, up = 0;
        foreach (var n in snap.Networks) { dl += n.DownloadBytesPerSec; up += n.UploadBytesPerSec; }
        NetSpeedText = $"↓ {PcSecurityCenter.Core.Utils.SizeFormat.Format((long)dl)}/s   ↑ {PcSecurityCenter.Core.Utils.SizeFormat.Format((long)up)}/s";

        Push(CpuSeries, snap.Cpu.UsagePercent);
        Push(MemSeries, snap.Memory.UsagePercent);
        Push(NetDownSeries, dl / 1024);
        Push(NetUpSeries, up / 1024);
    }

    private static void Push(ObservableCollection<double> series, double v)
    {
        series.Add(v);
        while (series.Count > MaxPoints) series.RemoveAt(0);
    }

    [RelayCommand]
    private async Task ApplyIntervalAsync()
    {
        _config.Current.PerformanceIntervalMs = IntervalMs;
        await _config.SaveAsync();
        _monitor.SetIntervalMs(IntervalMs);
    }
}
