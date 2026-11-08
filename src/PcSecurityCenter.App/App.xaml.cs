using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Scanning;
using PcSecurityCenter.Core.SecurityChecks;
using PcSecurityCenter.Data.Configuration;
using PcSecurityCenter.Data.Database;
using PcSecurityCenter.Data.Repositories;
using PcSecurityCenter.Platform.Defender;
using PcSecurityCenter.Platform.Maintenance;
using PcSecurityCenter.Platform.Network;
using PcSecurityCenter.Platform.Performance;
using PcSecurityCenter.Platform.Realtime;
using PcSecurityCenter.Platform.Security;
using PcSecurityCenter.Platform.SecurityChecks;
using PcSecurityCenter.Platform.Software;
using PcSecurityCenter.Platform.Startup;
using PcSecurityCenter.App.Services;
using PcSecurityCenter.App.ViewModels;
using PcSecurityCenter.App.Views;

namespace PcSecurityCenter.App;

public partial class App : Application
{
    public static IServiceProvider Services { get; private set; } = default!;

    private static Mutex? _singleInstanceMutex;

    /// <summary>最早的崩溃捕获：静态构造器先于一切 XAML 加载执行。</summary>
    static App()
    {
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            try
            {
                var ex = args.ExceptionObject as Exception;
                var crashFile = Path.Combine(Path.GetTempPath(), "psc_crash.log");
                File.AppendAllText(crashFile, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] FATAL: {ex}\n\n");
            }
            catch { }
        };
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        try
        {
            System.Windows.Forms.Application.SetHighDpiMode(System.Windows.Forms.HighDpiMode.PerMonitorV2);
            // 单实例：安全软件不应多开（避免扫描/隔离/配置的并发冲突）
            _singleInstanceMutex = new Mutex(true, "Global\\PcSecurityCenter_SingleInstance", out var createdNew);
            if (!createdNew)
            {
                MessageBox.Show("Windows 智能安全卫士已在运行中。", "Windows 智能安全卫士",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                Shutdown(0);
                return;
            }

            base.OnStartup(e);

            // 全局异常处理：记录日志 + 友好提示，绝不静默吞掉
            DispatcherUnhandledException += (_, args) =>
            {
                Serilog.Log.Error(args.Exception, "UI 线程未处理异常");
                MessageBox.Show($"发生未处理错误：{args.Exception.Message}\n\n详情请查看日志。", "Windows 智能安全卫士",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                args.Handled = true;
            };
            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
                Serilog.Log.Error(args.ExceptionObject as Exception, "非 UI 线程未处理异常");
            TaskScheduler.UnobservedTaskException += (_, args) =>
            {
                Serilog.Log.Error(args.Exception, "未观察的任务异常");
                args.SetObserved();
            };

            LoggingSetup.Initialize();
            Serilog.Log.Information("==== Windows 智能安全卫士 启动 ====");

            Services = BuildServices();

            // 1) 读取配置（小文件，同步一次）。此前从未调用 LoadAsync，
            //    导致重启后用户设置不生效——这里补上，主题/防护开关才有意义。
            var config = Services.GetRequiredService<IConfigService>();
            try { config.LoadAsync().GetAwaiter().GetResult(); }
            catch (Exception ex) { Serilog.Log.Warning(ex, "启动时读取配置失败，使用默认配置"); }

            // 2) 应用主题：必须在窗口创建前完成，保证第一帧就是用户选择的配色（默认亮色）
            ThemeService.Apply(config.Current.UseLightTheme);

            // 3) 后台预热 SQLite 建库（DDL），避免首次导航时才同步执行造成白屏
            _ = Task.Run(() =>
            {
                try { _ = Services.GetRequiredService<AppDatabase>(); }
                catch (Exception) { }
            });

            // 4) 后台预热 Defender 状态（异步且带 8 秒缓存，不阻塞 UI；与状态栏共用同一次结果）
            _ = Task.Run(async () =>
            {
                try { await Services.GetRequiredService<IDefenderClient>().GetStatusAsync(); }
                catch (Exception) { }
            });

            var window = new MainWindow();
            MainWindow = window;
            window.Show();
        }
        catch (Exception ex)
        {
            // 启动期崩溃：写临时崩溃日志 + 弹窗说明，绝不静默
            try
            {
                File.AppendAllText(Path.Combine(Path.GetTempPath(), "psc_crash.log"),
                    $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] STARTUP FAIL: {ex}\n\n");
            }
            catch { }
            MessageBox.Show($"启动失败：{ex.Message}\n\n崩溃详情已写入 %TEMP%\\psc_crash.log", "Windows 智能安全卫士",
                MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(-1);
        }
    }

    private static IServiceProvider BuildServices()
    {
        var services = new ServiceCollection();

        // 数据层
        services.AddSingleton<AppDatabase>(_ => new AppDatabase(AppPaths.DbFile));
        services.AddSingleton<ConfigService>();
        services.AddSingleton<IConfigService>(sp => sp.GetRequiredService<ConfigService>());
        services.AddSingleton<ScanRunRepository>();
        services.AddSingleton<ThreatRepository>();
        services.AddSingleton<SecurityEventRepository>();
        services.AddSingleton<CheckResultRepository>();
        services.AddSingleton<MaintenanceRunRepository>();

        // 平台层
        services.AddSingleton<IDefenderClient, DefenderClient>();
        services.AddSingleton<IPermissionService, WindowsPermissionService>();
        services.AddSingleton<IScoreCalculator, ScoreCalculator>();
        services.AddSingleton<ISecurityCheckService, SystemSecurityCheckService>();
        services.AddSingleton<IPerformanceMonitor, PerformanceCollector>();
        services.AddSingleton<INetworkMonitor, WindowsNetworkMonitor>();
        services.AddSingleton<IStartupManager, WindowsStartupManager>();
        services.AddSingleton<WindowsTasksAndServices>();
        services.AddSingleton<IInstalledAppsProvider, WindowsInstalledAppsProvider>();
        services.AddSingleton<IMaintenanceService, WindowsMaintenanceService>();
        services.AddSingleton<IQuarantineService>(_ => new QuarantineService(AppPaths.QuarantineDir));
        services.AddSingleton<IFileAnalysisService, PlatformFileAnalysisService>();
        services.AddSingleton<IScanRangeBuilder, ScanRangeBuilder>();
        services.AddSingleton<IScanEngine, SmartRiskEngine>();
        services.AddSingleton<IScanOrchestrator, ScanOrchestrator>();
        services.AddSingleton<WindowsTasksAndServices>();

        // 应用服务
        services.AddSingleton<ISecurityEventService, SecurityEventBus>();
        services.AddSingleton<INotificationService, AppNotificationService>();
        services.AddSingleton<IRealtimeProtector, WindowsRealtimeProtector>();
        services.AddSingleton<IDialogService, DialogService>();
        services.AddSingleton<NavigationService>();

        // ViewModel
        services.AddSingleton<DashboardViewModel>();
        services.AddSingleton<ScanViewModel>();
        services.AddSingleton<ProtectionViewModel>();
        services.AddSingleton<NetworkViewModel>();
        services.AddSingleton<SystemSecurityViewModel>();
        services.AddSingleton<PerformanceViewModel>();
        services.AddSingleton<MaintenanceViewModel>();
        services.AddSingleton<StartupSoftwareViewModel>();
        services.AddSingleton<AdvancedToolsViewModel>();
        services.AddSingleton<FileAnalysisViewModel>();
        services.AddSingleton<ReportCenterViewModel>();
        services.AddSingleton<SettingsViewModel>();

        return services.BuildServiceProvider();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        try
        {
            Services.GetService<IRealtimeProtector>()?.Stop();
            Services.GetService<IPerformanceMonitor>()?.Stop();
            Services.GetService<ConfigService>()?.SaveAsync().Wait(2000);
        }
        catch (Exception) { }
        Serilog.Log.Information("==== 应用退出 ====");
        Serilog.Log.CloseAndFlush();
        try { _singleInstanceMutex?.ReleaseMutex(); } catch (Exception) { }
        base.OnExit(e);
    }
}
