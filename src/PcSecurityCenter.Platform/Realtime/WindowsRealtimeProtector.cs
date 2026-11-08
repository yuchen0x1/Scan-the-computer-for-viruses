using System.Diagnostics;
using System.IO;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Core.Scanning;
using PcSecurityCenter.Platform.Security;

namespace PcSecurityCenter.Platform.Realtime;

/// <summary>
/// 实时防护（资源友好设计）：
/// - FileSystemWatcher 监听启动文件夹（事件驱动，零轮询）；
/// - 低频轮询（默认 15s，可配置）：注册表 Run 键变化、新增进程（临时目录中的进程）、Defender 状态；
/// - 全部规则为"可解释风险提示"，绝不高 CPU 进程即判病毒；
/// - 事件经 ISecurityEventService 发布并落库。
/// </summary>
public class WindowsRealtimeProtector : IRealtimeProtector
{
    private readonly ISecurityEventService _events;
    private readonly IDefenderClient _defender;
    private readonly IConfigService _config;
    private readonly List<FileSystemWatcher> _watchers = new();
    private System.Timers.Timer? _pollTimer;
    private System.Timers.Timer? _defenderTimer;
    private readonly HashSet<int> _knownProcessIds = new();
    private readonly Dictionary<string, string> _knownRunEntries = new(StringComparer.OrdinalIgnoreCase);
    private bool _lastDefenderRt = true;
    private readonly object _lock = new();
    private readonly Queue<SecurityEvent> _recent = new();

    public bool IsRunning { get; private set; }
    public event EventHandler<SecurityEvent>? EventRaised;
    public List<SecurityEvent> RecentEvents
    {
        get { lock (_lock) return _recent.ToList(); }
    }

    public WindowsRealtimeProtector(ISecurityEventService events, IDefenderClient defender, IConfigService config)
    {
        _events = events;
        _defender = defender;
        _config = config;
        _events.EventPublished += (_, e) =>
        {
            lock (_lock)
            {
                _recent.Enqueue(e);
                while (_recent.Count > 100) _recent.Dequeue();
            }
            EventRaised?.Invoke(this, e);
        };
    }

    public void Start()
    {
        if (IsRunning) return;
        IsRunning = true;

        // 1. 启动文件夹监控（事件驱动）
        foreach (var dir in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        })
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
            try
            {
                var w = new FileSystemWatcher(dir)
                {
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime,
                    EnableRaisingEvents = true,
                };
                w.Created += (_, e) => OnStartupFolderChange(e.FullPath, dir);
                _watchers.Add(w);
            }
            catch (Exception) { }
        }

        // 2. 低频轮询
        _pollTimer = new System.Timers.Timer(Math.Max(5, _config.Current.RealtimePollIntervalSec) * 1000) { AutoReset = true };
        _pollTimer.Elapsed += (_, _) => _ = PollAsync();
        _pollTimer.Start();

        // 3. Defender 状态监控（1 分钟一次）
        _defenderTimer = new System.Timers.Timer(60_000) { AutoReset = true };
        _defenderTimer.Elapsed += (_, _) => _ = PollDefenderAsync();
        _defenderTimer.Start();

        // 初始化基线
        SnapshotRunEntries();
        foreach (var p in Process.GetProcesses()) { try { _knownProcessIds.Add(p.Id); } catch (Exception) { } }
        _ = PollDefenderAsync();
        Serilog.Log.Information("实时防护已启动（轮询间隔 {Sec}s）", _config.Current.RealtimePollIntervalSec);
    }

    public void Stop()
    {
        if (!IsRunning) return;
        IsRunning = false;
        foreach (var w in _watchers) { w.EnableRaisingEvents = false; w.Dispose(); }
        _watchers.Clear();
        _pollTimer?.Stop(); _pollTimer?.Dispose(); _pollTimer = null;
        _defenderTimer?.Stop(); _defenderTimer?.Dispose(); _defenderTimer = null;
        Serilog.Log.Information("实时防护已停止");
    }

    // ---------- 启动文件夹事件 ----------
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> _lastEventTicks = new();

    private void OnStartupFolderChange(string fullPath, string dir)
    {
        try
        {
            if (!File.Exists(fullPath)) return;
            // 同一路径 2 秒内的重复事件只处理一次，防止事件风暴逐事件同步读文件
            var now = Environment.TickCount64;
            if (_lastEventTicks.TryGetValue(fullPath, out var last) && now - last < 2000) return;
            _lastEventTicks[fullPath] = now;
            if (_lastEventTicks.Count > 1024) _lastEventTicks.Clear();
            var ext = Path.GetExtension(fullPath).ToLowerInvariant();
            var indicators = SmartRiskEngine.ScriptContentIndicators(fullPath);
            var severity = indicators.Count > 0 ? ThreatSeverity.High : ThreatSeverity.Medium;
            _ = _events.PublishAsync(new SecurityEvent
            {
                Type = SecurityEventType.StartupChange,
                Severity = severity,
                Title = "启动文件夹出现新文件",
                Detail = $"{fullPath}（{dir}）" + (indicators.Count > 0 ? "；脚本内容包含可疑行为：" + string.Join("；", indicators) : "。请确认是否为本人添加。"),
            });
        }
        catch (Exception) { }
    }

    // ---------- 低频轮询 ----------
    private int _pollBusy;
    private async Task PollAsync()
    {
        if (Interlocked.Exchange(ref _pollBusy, 1) == 1) return; // 重入保护：上一轮未完则跳过本轮
        try
        {
            CheckRunKeyChanges();
            CheckNewProcesses();
        }
        catch (Exception ex)
        {
            Serilog.Log.Debug(ex, "实时防护轮询异常（已忽略）");
        }
        finally { Interlocked.Exchange(ref _pollBusy, 0); }
        await Task.CompletedTask;
    }

    private void SnapshotRunEntries()
    {
        foreach (var (hive, sub) in RunKeys)
        {
            foreach (var name in RegistryHelper.GetValueNames(hive, sub))
            {
                var val = RegistryHelper.GetStringValue(hive, sub, name);
                if (val != null) _knownRunEntries[sub + "\\" + name] = val;
            }
        }
    }

    private static readonly (Microsoft.Win32.RegistryKey hive, string sub)[] RunKeys =
    [
        (Microsoft.Win32.Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (Microsoft.Win32.Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
    ];

    private void CheckRunKeyChanges()
    {
        var current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (hive, sub) in RunKeys)
            foreach (var name in RegistryHelper.GetValueNames(hive, sub))
            {
                var val = RegistryHelper.GetStringValue(hive, sub, name);
                if (val != null) current[sub + "\\" + name] = val;
            }

        foreach (var (key, val) in current)
            if (!_knownRunEntries.TryGetValue(key, out var old) || old != val)
                _ = _events.PublishAsync(new SecurityEvent
                {
                    Type = SecurityEventType.StartupChange,
                    Severity = ThreatSeverity.Medium,
                    Title = "检测到注册表启动项变化",
                    Detail = $"新增或修改：{key} = {val}",
                });
        foreach (var key in _knownRunEntries.Keys.Where(k => !current.ContainsKey(k)).ToList())
            _ = _events.PublishAsync(new SecurityEvent
            {
                Type = SecurityEventType.StartupChange,
                Severity = ThreatSeverity.Info,
                Title = "注册表启动项被移除",
                Detail = key,
            });
        _knownRunEntries.Clear();
        foreach (var (key, val) in current) _knownRunEntries[key] = val;
    }

    private void CheckNewProcesses()
    {
        var current = new List<Process>();
        try { current = Process.GetProcesses().ToList(); } catch (Exception) { return; }

        foreach (var p in current)
        {
            try
            {
                if (_knownProcessIds.Contains(p.Id)) continue;
                _knownProcessIds.Add(p.Id);
                if (p.Id <= 4) continue;

                string path = "";
                try { path = p.MainModule?.FileName ?? ""; } catch (Exception) { }
                if (string.IsNullOrEmpty(path)) continue;

                var temp = Path.GetTempPath();
                var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (path.StartsWith(temp, StringComparison.OrdinalIgnoreCase))
                {
                    _ = _events.PublishAsync(new SecurityEvent
                    {
                        Type = SecurityEventType.RealtimeDetection,
                        Severity = ThreatSeverity.Medium,
                        Title = "临时目录中的新进程",
                        Detail = $"{p.ProcessName}（PID {p.Id}）从 {path} 启动。临时目录运行的程序需留意来源；若为本人操作（安装包/更新程序）可忽略。",
                    });
                }
            }
            catch (Exception) { }
            finally { try { p.Dispose(); } catch { } }
        }

        // 清理已退出进程记录，避免集合无限增长
        if (_knownProcessIds.Count > 2000)
            _knownProcessIds.Clear();
    }

    private int _defenderPollBusy;
    private async Task PollDefenderAsync()
    {
        if (Interlocked.Exchange(ref _defenderPollBusy, 1) == 1) return; // 重入保护
        try
        {
            var st = await _defender.GetStatusAsync().ConfigureAwait(false);
            if (st.Installed && _lastDefenderRt && !st.RealTimeProtection)
            {
                await _events.PublishAsync(new SecurityEvent
                {
                    Type = SecurityEventType.RealtimeDetection,
                    Severity = ThreatSeverity.High,
                    Title = "Defender 实时防护被关闭",
                    Detail = "检测到 Microsoft Defender 实时保护状态变为关闭。若非本人操作，请立即到 Windows 安全中心重新开启。",
                }).ConfigureAwait(false);
            }
            _lastDefenderRt = st.RealTimeProtection;
        }
        catch (Exception) { }
        finally { Interlocked.Exchange(ref _defenderPollBusy, 0); }
    }

    public void Dispose()
    {
        Stop();
        GC.SuppressFinalize(this);
    }
}
