using System.Windows;
using System.Windows.Media;
using Microsoft.Extensions.DependencyInjection;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Data.Repositories;
using PcSecurityCenter.App.Views;
using PcSecurityCenter.App.ViewModels;

namespace PcSecurityCenter.App.Services;

/// <summary>应用内事件总线：发布并持久化安全事件。</summary>
public class SecurityEventBus : ISecurityEventService
{
    private readonly SecurityEventRepository _repo;
    public event EventHandler<SecurityEvent>? EventPublished;

    public SecurityEventBus(SecurityEventRepository repo) => _repo = repo;

    public async Task PublishAsync(SecurityEvent evt)
    {
        try { _repo.Insert(evt); } catch (Exception ex) { Serilog.Log.Error(ex, "事件落库失败"); }
        EventPublished?.Invoke(this, evt);
        await Task.CompletedTask;
    }

    // 真异步：SQLite 查询放线程池，不占用 UI 线程
    public Task<List<SecurityEvent>> GetRecentAsync(int count = 50) =>
        Task.Run(() => _repo.GetRecent(count));
}

/// <summary>应用内通知（Toast 触发 + 主窗口通知中心）。</summary>
public class AppNotificationService : INotificationService
{
    public event EventHandler<(string Title, string Message, ThreatSeverity Severity)>? Notified;

    public void Notify(string title, string message, ThreatSeverity severity = ThreatSeverity.Info)
        => Notified?.Invoke(this, (title, message, severity));
}

/// <summary>导航页定义。</summary>
public enum PageKind
{
    Dashboard,      // 安全驾驶舱
    Scan,           // 病毒查杀
    Protection,     // 实时防护
    Network,        // 网络安全
    SystemSecurity, // 系统安全
    Performance,    // 性能监控
    Maintenance,    // 系统维护
    Startup,        // 启动项管理
    Software,       // 软件管理
    AdvancedTools,  // 高级工具
    FileAnalysis,   // 文件分析
    Reports,        // 安全报告
    Settings,       // 设置中心
    Update,         // 更新中心
}

/// <summary>页面激活感知：实现该接口的 ViewModel 会在导航进入/离开时收到通知，
/// 用于暂停/恢复定时器等后台工作（避免切页后仍在后台空转）。</summary>
public interface IPageActivatable
{
    void OnPageActivated();
    void OnPageDeactivated();
}

/// <summary>导航服务：页面创建与切换（懒加载 + 缓存）。</summary>
public class NavigationService
{
    private readonly Dictionary<PageKind, object> _cache = new();
    private readonly Func<PageKind, object> _pageFactory;
    private readonly IServiceProvider _sp;
    private PageKind _current;

    public NavigationService(IServiceProvider sp)
    {
        _sp = sp;
        _pageFactory = kind => kind switch
        {
            PageKind.Dashboard => new DashboardPage(_sp.GetRequiredService<DashboardViewModel>()),
            PageKind.Scan => new ScanPage(_sp.GetRequiredService<ScanViewModel>()),
            PageKind.Protection => new ProtectionPage(_sp.GetRequiredService<ProtectionViewModel>()),
            PageKind.Network => new NetworkPage(_sp.GetRequiredService<NetworkViewModel>()),
            PageKind.SystemSecurity => new SystemSecurityPage(_sp.GetRequiredService<SystemSecurityViewModel>()),
            PageKind.Performance => new PerformancePage(_sp.GetRequiredService<PerformanceViewModel>()),
            PageKind.Maintenance => new MaintenancePage(_sp.GetRequiredService<MaintenanceViewModel>()),
            PageKind.Startup => new StartupPage(_sp.GetRequiredService<StartupSoftwareViewModel>()),
            PageKind.Software => new SoftwarePage(_sp.GetRequiredService<StartupSoftwareViewModel>()),
            PageKind.AdvancedTools => new AdvancedToolsPage(_sp.GetRequiredService<AdvancedToolsViewModel>()),
            PageKind.FileAnalysis => new FileAnalysisPage(_sp.GetRequiredService<FileAnalysisViewModel>()),
            PageKind.Reports => new ReportCenterPage(_sp.GetRequiredService<ReportCenterViewModel>()),
            PageKind.Settings => new SettingsPage(_sp.GetRequiredService<SettingsViewModel>()),
            PageKind.Update => new UpdatePage(_sp.GetRequiredService<UpdateViewModel>()),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
    }

    public object Navigate(PageKind kind)
    {
        // 离开上一页：暂停其后台定时器
        if (_cache.TryGetValue(_current, out var prev) && prev is FrameworkElement { DataContext: IPageActivatable deactivate })
            deactivate.OnPageDeactivated();

        if (!_cache.TryGetValue(kind, out var page))
        {
            page = _pageFactory(kind);
            _cache[kind] = page;
        }
        _current = kind;

        // 进入新页：恢复其后台定时器
        if (page is FrameworkElement { DataContext: IPageActivatable activate })
            activate.OnPageActivated();

        return page;
    }
}

/// <summary>主题化对话框服务（异步，由 MainWindow 提供宿主；不阻塞 UI 线程）。</summary>
public interface IDialogService
{
    Task<bool> ConfirmAsync(string title, string message, string confirmText = "确认", bool danger = false);
    Task<(bool ok, string input)> PromptAsync(string title, string message, string defaultValue = "");
    Task InfoAsync(string title, string message);
}

public class DialogService : IDialogService
{
    public event Action<string, string, string, bool, TaskCompletionSource<bool>>? ConfirmRequested;
    public event Action<string, string, string, TaskCompletionSource<(bool, string)>>? PromptRequested;
    public event Action<string, string, TaskCompletionSource<bool>>? InfoRequested;

    public Task<bool> ConfirmAsync(string title, string message, string confirmText = "确认", bool danger = false)
    {
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        ConfirmRequested?.Invoke(title, message, confirmText, danger, tcs);
        return tcs.Task;
    }

    public Task<(bool ok, string input)> PromptAsync(string title, string message, string defaultValue = "")
    {
        var tcs = new TaskCompletionSource<(bool, string)>(TaskCreationOptions.RunContinuationsAsynchronously);
        PromptRequested?.Invoke(title, message, defaultValue, tcs);
        return tcs.Task;
    }

    public Task InfoAsync(string title, string message)
    {
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        InfoRequested?.Invoke(title, message, tcs);
        return tcs.Task;
    }
}

/// <summary>UI 线程调度助手。</summary>
public static class Ui
{
    public static void Post(Action action)
    {
        var app = Application.Current;
        if (app == null) return;
        if (app.Dispatcher.CheckAccess()) action();
        else app.Dispatcher.BeginInvoke(action);
    }
}

/// <summary>状态色工具。</summary>
public static class SeverityBrush
{
    public static Brush For(ThreatSeverity s) => s switch
    {
        ThreatSeverity.Critical or ThreatSeverity.High => (Brush)Application.Current.Resources["BrushDanger"]!,
        ThreatSeverity.Medium => (Brush)Application.Current.Resources["BrushWarn"]!,
        ThreatSeverity.Low => (Brush)Application.Current.Resources["BrushAccent"]!,
        _ => (Brush)Application.Current.Resources["BrushTextSecondary"]!,
    };

    public static Brush ForCheck(CheckStatus s) => s switch
    {
        CheckStatus.Ok => (Brush)Application.Current.Resources["BrushOk"]!,
        CheckStatus.Warning => (Brush)Application.Current.Resources["BrushWarn"]!,
        CheckStatus.Risk => (Brush)Application.Current.Resources["BrushDanger"]!,
        _ => (Brush)Application.Current.Resources["BrushTextMuted"]!,
    };
}
