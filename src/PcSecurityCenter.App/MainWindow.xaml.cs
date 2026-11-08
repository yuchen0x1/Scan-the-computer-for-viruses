using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Microsoft.Extensions.DependencyInjection;
using PcSecurityCenter.App.Services;
using PcSecurityCenter.App.ViewModels;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;

namespace PcSecurityCenter.App;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private readonly NavigationService _navigation;
    private readonly IDialogService _dialogs;
    private readonly INotificationService _notifications;
    private readonly IDefenderClient _defender;
    private readonly IPermissionService _permission;
    private readonly IRealtimeProtector _protector;
    private readonly System.Windows.Forms.NotifyIcon _trayIcon;
    private readonly System.Windows.Forms.ContextMenuStrip _trayMenu;
    private bool _allowExit;
    private bool _trayHintShown;
    private readonly List<(string title, string msg, ThreatSeverity sev, DateTime time)> _notifications2 = new();

    public string GlobalStatusText { get; set; } = "评估中…";
    public Brush GlobalStatusBrush { get; set; } = Brushes.Gray;
    public string EngineStatusText { get; set; } = "引擎检测中…";
    public string ElevationHint { get; set; } = "";

    public event PropertyChangedEventHandler? PropertyChanged;

    private PageKind _currentPage = PageKind.Dashboard;

    public MainWindow()
    {
        // 服务必须在 InitializeComponent 之前获取：XAML 中 IsChecked="True" 会在加载期间触发 Checked 事件
        _navigation = App.Services.GetRequiredService<NavigationService>();
        _dialogs = App.Services.GetRequiredService<IDialogService>();
        _notifications = App.Services.GetRequiredService<INotificationService>();
        _defender = App.Services.GetRequiredService<IDefenderClient>();
        _permission = App.Services.GetRequiredService<IPermissionService>();
        _protector = App.Services.GetRequiredService<IRealtimeProtector>();

        InitializeComponent();
        DataContext = this;
        ElevationHint = _permission.ElevationHint;

        _trayMenu = new System.Windows.Forms.ContextMenuStrip();
        _trayMenu.Items.Add("打开 Windows 智能安全卫士", null, (_, _) => RestoreFromTray());
        _trayMenu.Items.Add("退出", null, (_, _) => ExitApplication());
        _trayIcon = new System.Windows.Forms.NotifyIcon
        {
            Icon = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? "")
                   ?? System.Drawing.SystemIcons.Shield,
            Text = "Windows 智能安全卫士",
            Visible = true,
            ContextMenuStrip = _trayMenu,
        };
        _trayIcon.DoubleClick += (_, _) => RestoreFromTray();
        _trayIcon.MouseClick += (_, e) =>
        {
            if (e.Button == System.Windows.Forms.MouseButtons.Left) RestoreFromTray();
        };
        Closing += MainWindow_Closing;
        VersionText.Text = $"v{typeof(MainWindow).Assembly.GetName().Version?.ToString(3) ?? "1.0.0"}";

        // 对话框事件接线（异步，不阻塞 UI 线程）
        if (_dialogs is DialogService ds)
        {
            ds.ConfirmRequested += (title, msg, ok, danger, tcs) => ShowConfirm(title, msg, ok, danger, tcs);
            ds.PromptRequested += (title, msg, def, tcs) => ShowPrompt(title, msg, def, tcs);
            ds.InfoRequested += (title, msg, tcs) => ShowInfo(title, msg, tcs);
        }

        // 通知接线
        _notifications.Notified += (_, e) => ShowToast(e.Title, e.Message, e.Severity);

        // 实时防护事件 → 通知 + 铃铛红点
        _protector.EventRaised += (_, evt) =>
        {
            if (evt.Severity >= ThreatSeverity.Medium)
            {
                Ui.Post(() =>
                {
                    BellDot.Visibility = Visibility.Visible;
                    ShowToast(evt.Title, evt.Detail, evt.Severity);
                });
            }
        };

        // 实时防护 + Defender 状态
        _ = InitStatusBarAsync();

        // 启动实时防护（配置开关）。
        // Start() 内部要枚举全部进程并读取注册表基线，必须放到线程池执行——
        // 否则这段同步工作会把窗口出现的时间推迟数百毫秒到数秒。
        var config = App.Services.GetRequiredService<IConfigService>();
        if (config.Current.RealtimeEnabled)
        {
            var protector = _protector;
            _ = Task.Run(() =>
            {
                try { protector.Start(); }
                catch (Exception ex) { Serilog.Log.Warning(ex, "实时防护启动失败"); }
            });
        }

        // 默认页面
        NavigateTo(PageKind.Dashboard);
    }

    private async Task InitStatusBarAsync()
    {
        try
        {
            var st = await _defender.GetStatusAsync();
            EngineStatusText = st.Installed && st.EngineAvailable
                ? $"检测引擎：Microsoft Defender（病毒库 {st.SignatureLastUpdated:MM-dd HH:mm}）"
                : "检测引擎：SmartRisk（Defender 不可用，检测能力受限）";
            GlobalStatusText = st.RealTimeProtection ? "防护运行中" : "防护状态异常";
            GlobalStatusBrush = st.RealTimeProtection
                ? (Brush)Application.Current.Resources["BrushOk"]!
                : (Brush)Application.Current.Resources["BrushDanger"]!;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(EngineStatusText)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(GlobalStatusText)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(GlobalStatusBrush)));
        }
        catch (Exception)
        {
            EngineStatusText = "检测引擎：不可用";
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(EngineStatusText)));
        }
    }

    // ============ 导航 ============
    private void Nav_Click(object sender, RoutedEventArgs e)
    {
        var kind = sender switch
        {
            _ when ReferenceEquals(sender, NavDashboard) => PageKind.Dashboard,
            _ when ReferenceEquals(sender, NavScan) => PageKind.Scan,
            _ when ReferenceEquals(sender, NavProtection) => PageKind.Protection,
            _ when ReferenceEquals(sender, NavNetwork) => PageKind.Network,
            _ when ReferenceEquals(sender, NavSystemSecurity) => PageKind.SystemSecurity,
            _ when ReferenceEquals(sender, NavPerformance) => PageKind.Performance,
            _ when ReferenceEquals(sender, NavMaintenance) => PageKind.Maintenance,
            _ when ReferenceEquals(sender, NavStartup) => PageKind.Startup,
            _ when ReferenceEquals(sender, NavSoftware) => PageKind.Software,
            _ when ReferenceEquals(sender, NavAdvanced) => PageKind.AdvancedTools,
            _ when ReferenceEquals(sender, NavFileAnalysis) => PageKind.FileAnalysis,
            _ when ReferenceEquals(sender, NavReports) => PageKind.Reports,
            _ when ReferenceEquals(sender, NavSettings) => PageKind.Settings,
            _ => PageKind.Dashboard,
        };
        NavigateTo(kind);
    }

    private void NavigateTo(PageKind kind)
    {
        // XAML 加载期间 IsChecked="True" 会触发 Checked 事件，此时导航服务/内容宿主可能尚未就绪
        if (_navigation == null || ContentHost == null) return;
        _currentPage = kind;
        var page = (UIElement)_navigation.Navigate(kind);
        // 淡入动画
        ContentHost.Content = page;
        page.Opacity = 0;
        var anim = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(260))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };
        page.BeginAnimation(UIElement.OpacityProperty, anim);
    }

    // ============ 窗口控制 ============
    private void TopBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        }
        else DragMove();
    }
    private void MinimizeButton_Click(object sender, RoutedEventArgs e) => HideToTray();
    private void MaximizeButton_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    // 最小化与关闭都收进通知区域：窗口从桌面和任务栏消失，进程与实时防护继续运行。
    private void HideToTray()
    {
        Hide();
        if (_trayHintShown) return;
        _trayHintShown = true;
        try
        {
            _trayIcon.ShowBalloonTip(2500, "Windows 智能安全卫士",
                "已收进系统托盘，单击图标恢复窗口，右键菜单可退出。",
                System.Windows.Forms.ToolTipIcon.Info);
        }
        catch (Exception) { }   // 通知区域不可用时不影响隐藏逻辑
    }

    // 点击关闭或 Alt+F4 时隐藏到通知区域，避免误退出并让实时防护继续运行。
    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (_allowExit)
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            _trayMenu.Dispose();
            return;
        }

        e.Cancel = true;
        Hide();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => HideToTray();

    private void RestoreFromTray()
    {
        Dispatcher.BeginInvoke(() =>
        {
            if (!IsVisible) Show();
            if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
            Activate();
        });
    }

    private void ExitApplication()
    {
        Dispatcher.BeginInvoke(() =>
        {
            _allowExit = true;
            Application.Current.Shutdown();
        });
    }

    // ============ 标题栏圆角（DWM） ============
    // Windows 11 的 DWM 负责把窗口四角裁成圆角；DWMWCP_ROUND = 8px 标准圆角，
    // 视觉上「圆一点但不夸张」，且不改变窗口命中区域（最大化/贴边仍由系统处理）。
    private const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    private const int DWMWCP_ROUND = 2;
    private const int DWMWCP_DONOTROUND = 1;

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    private IntPtr _hwnd;

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        _hwnd = new WindowInteropHelper(this).Handle;
        ApplyCornerPreference(DWMWCP_ROUND);
        StateChanged += (_, _) =>
        {
            // 最大化时取消圆角，避免四角露出桌面缝隙
            ApplyCornerPreference(WindowState == WindowState.Maximized ? DWMWCP_DONOTROUND : DWMWCP_ROUND);
            UpdateMaximizeIcon();
            // 系统级最小化（Win+下、任务栏点击）同样收进通知区域
            if (WindowState == WindowState.Minimized) HideToTray();
        };
        UpdateMaximizeIcon();
    }

    private void ApplyCornerPreference(int preference)
    {
        if (_hwnd == IntPtr.Zero) return;
        try
        {
            var pref = preference;
            _ = DwmSetWindowAttribute(_hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ref pref, sizeof(int));
        }
        catch (EntryPointNotFoundException) { }   // Windows 10：无此属性，保持直角
        catch (DllNotFoundException) { }
    }

    /// <summary>最大化时把方框图标换成「还原」双框图标。</summary>
    private void UpdateMaximizeIcon()
    {
        if (MaximizeIcon == null) return;
        // 还原态：后框只画未被前框遮挡的 L 形边，前框为完整方框
        MaximizeIcon.Data = WindowState == WindowState.Maximized
            ? Geometry.Parse("M1,4 H8 V11 H1 Z M4,1 H11 V8 H8 M4,1 V4")
            : Geometry.Parse("M1,1 H11 V11 H1 Z");
    }

    private void SettingsButton_Click(object sender, RoutedEventArgs e)
    {
        NavSettings.IsChecked = true;
        NavigateTo(PageKind.Settings);
    }

    // ============ 通知中心 ============
    private void BellButton_Click(object sender, RoutedEventArgs e)
    {
        BellDot.Visibility = Visibility.Collapsed;
        if (NotificationCenter.Visibility == Visibility.Visible)
        {
            NotificationCenter.Visibility = Visibility.Collapsed;
            return;
        }
        NotificationList.ItemsSource = _notifications2
            .OrderByDescending(n => n.time).Take(50)
            .Select(n => new NotificationItemVm(n.title, n.msg, n.sev, n.time)).ToList();
        NotificationCenter.Visibility = Visibility.Visible;
    }

    private void CloseNotifications_Click(object sender, RoutedEventArgs e)
        => NotificationCenter.Visibility = Visibility.Collapsed;

    private void ShowToast(string title, string message, ThreatSeverity severity)
    {
        _notifications2.Add((title, message, severity, DateTime.Now));
        if (_notifications2.Count > 200) _notifications2.RemoveAt(0);
        if (NotificationCenter.Visibility == Visibility.Visible) return;

        Ui.Post(() =>
        {
            ToastTitle.Text = title;
            ToastMessage.Text = message;
            var brush = SeverityBrush.For(severity);
            // 卡片底色跟随主题资源（亮/暗自适应）
            ToastCard.Background = Application.Current?.TryFindResource("BrushPopupBg") as Brush
                                   ?? ToastCard.Background;
            ToastTitle.Foreground = brush;
            ToastHost.Visibility = Visibility.Visible;
            ToastHost.Opacity = 0;
            ToastHost.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220)));
            var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(4.5) };
            timer.Tick += (_, _) =>
            {
                timer.Stop();
                var fade = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(300));
                fade.Completed += (_, _) => ToastHost.Visibility = Visibility.Collapsed;
                ToastHost.BeginAnimation(OpacityProperty, fade);
            };
            timer.Start();
        });
    }

    // ============ 对话框（异步 TCS 驱动） ============
    private TaskCompletionSource<bool>? _confirmTcs;
    private TaskCompletionSource<(bool, string)>? _promptTcs;

    private void ShowConfirm(string title, string message, string okText, bool danger, TaskCompletionSource<bool> tcs)
    {
        Ui.Post(() =>
        {
            _confirmTcs = tcs;
            DialogTitle.Text = title;
            DialogMessage.Text = message;
            DialogInput.Visibility = Visibility.Collapsed;
            DialogOk.Content = okText;
            DialogOk.Style = danger ? (Style)FindResource("DangerButton") : (Style)FindResource("PrimaryButton");
            DialogCancel.Visibility = Visibility.Visible;
            DialogHost.Visibility = Visibility.Visible;
        });
    }

    private void ShowPrompt(string title, string message, string def, TaskCompletionSource<(bool, string)> tcs)
    {
        Ui.Post(() =>
        {
            _promptTcs = tcs;
            DialogTitle.Text = title;
            DialogMessage.Text = message;
            DialogInput.Visibility = Visibility.Visible;
            DialogInput.Text = def;
            DialogOk.Content = "确定";
            DialogOk.Style = (Style)FindResource("PrimaryButton");
            DialogCancel.Visibility = Visibility.Visible;
            DialogHost.Visibility = Visibility.Visible;
        });
    }

    private void ShowInfo(string title, string message, TaskCompletionSource<bool> tcs)
    {
        Ui.Post(() =>
        {
            _confirmTcs = tcs;
            DialogTitle.Text = title;
            DialogMessage.Text = message;
            DialogInput.Visibility = Visibility.Collapsed;
            DialogOk.Content = "知道了";
            DialogOk.Style = (Style)FindResource("PrimaryButton");
            DialogCancel.Visibility = Visibility.Collapsed;
            DialogHost.Visibility = Visibility.Visible;
        });
    }

    private void CompleteDialog(bool result)
    {
        DialogHost.Visibility = Visibility.Collapsed;
        _confirmTcs?.TrySetResult(result);
        if (_promptTcs != null) _promptTcs.TrySetResult((result, DialogInput.Text));
        _confirmTcs = null;
        _promptTcs = null;
    }

    private void DialogOk_Click(object sender, RoutedEventArgs e) => CompleteDialog(true);
    private void DialogCancel_Click(object sender, RoutedEventArgs e) => CompleteDialog(false);
}

/// <summary>通知中心条目 VM。</summary>
public record NotificationItemVm(string Title, string Message, ThreatSeverity Severity, DateTime Time)
{
    public string TimeText => Time.ToString("MM-dd HH:mm:ss");
    public Brush SeverityBrush => SeverityBrush2(Severity);
    private static Brush SeverityBrush2(ThreatSeverity s) => s switch
    {
        ThreatSeverity.Critical or ThreatSeverity.High => (Brush)Application.Current.Resources["BrushDanger"]!,
        ThreatSeverity.Medium => (Brush)Application.Current.Resources["BrushWarn"]!,
        _ => (Brush)Application.Current.Resources["BrushTextSecondary"]!,
    };
}
