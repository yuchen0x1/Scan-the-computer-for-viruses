using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Data.Repositories;
using PcSecurityCenter.App.Services;
using PcSecurityCenter.Core.Reporting;
using PcSecurityCenter.Platform.Startup;

namespace PcSecurityCenter.App.ViewModels;

/// <summary>系统维护页。</summary>
public partial class MaintenanceViewModel : ObservableObject
{
    private readonly IMaintenanceService _maintenance;
    private readonly IPermissionService _permission;
    private readonly MaintenanceRunRepository _repo;
    private readonly IDialogService _dialogs;
    private readonly ISecurityEventService _events;

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _statusText = "点击「扫描可清理项」查看本机可安全清理的内容。";
    [ObservableProperty] private long _selectedBytes;
    [ObservableProperty] private string _diskAnalysisText = "";
    [ObservableProperty] private string _sfcOutput = "";
    [ObservableProperty] private string _dismOutput = "";
    [ObservableProperty] private string _restorePointsText = "";
    [ObservableProperty] private string _chkOutput = "";

    public ObservableCollection<MaintenanceCleanItem> CleanItems { get; } = new();
    public ObservableCollection<DiskSpaceItem> DiskItems { get; } = new();
    public ObservableCollection<RestorePointInfo> RestorePoints { get; } = new();

    public MaintenanceViewModel(IMaintenanceService maintenance, IPermissionService permission,
        MaintenanceRunRepository repo, IDialogService dialogs, ISecurityEventService events)
    {
        _maintenance = maintenance;
        _permission = permission;
        _repo = repo;
        _dialogs = dialogs;
        _events = events;
    }

    [RelayCommand]
    private async Task ScanCleanableAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        StatusText = "正在扫描可清理项…";
        CleanItems.Clear();
        try
        {
            var items = await _maintenance.ScanCleanableAsync();
            foreach (var i in items) CleanItems.Add(i);
            StatusText = items.Count > 0
                ? $"发现 {items.Count} 类可清理内容，合计 {PcSecurityCenter.Core.Utils.SizeFormat.Format(items.Sum(x => x.SizeBytes))}。请勾选后清理。"
                : "未发现可安全清理的内容。";
            UpdateSelected();
        }
        catch (Exception ex)
        {
            StatusText = "扫描失败：" + ex.Message;
        }
        finally { IsBusy = false; }
    }

    public void UpdateSelected() =>
        SelectedBytes = CleanItems.Where(x => x.Selected).Sum(x => x.SizeBytes);

    [RelayCommand]
    private async Task CleanAsync()
    {
        if (IsBusy) return;
        var selected = CleanItems.Where(x => x.Selected).ToList();
        if (selected.Count == 0)
        {
            await _dialogs.InfoAsync("清理", "请先勾选要清理的项目。");
            return;
        }
        var ok = await _dialogs.ConfirmAsync("执行清理",
            $"将清理 {selected.Count} 类内容，预计释放 {PcSecurityCenter.Core.Utils.SizeFormat.Format(selected.Sum(x => x.SizeBytes))}。\n\n" +
            "安全规则：只删除普通文件、跳过使用中的文件、不删除任何目录结构、不触碰系统关键文件。\n\n确认执行？",
            "开始清理", danger: true);
        if (!ok) return;

        IsBusy = true;
        var startedAt = DateTime.Now;
        try
        {
            var (freed, files) = await _maintenance.CleanAsync(selected);
            // 需要管理员的项目单独引导
            var adminItems = selected.Where(x => x.RequiresAdmin).ToList();
            var record = new MaintenanceRunRecord
            {
                StartedAt = startedAt, FinishedAt = DateTime.Now,
                Action = "清理：" + string.Join("、", selected.Select(x => x.Name)),
                Detail = $"删除 {files} 个文件", FreedBytes = freed, Success = true,
            };
            _repo.Insert(record);
            StatusText = $"清理完成：释放 {PcSecurityCenter.Core.Utils.SizeFormat.Format(freed)}，删除 {files} 个文件。";
            if (adminItems.Count > 0)
                StatusText += $"\n注意：{adminItems.Count} 类需要管理员权限的项未处理（如系统临时文件/更新缓存），可创建还原点后手动处理或以管理员运行本工具。";
            await _events.PublishAsync(new SecurityEvent
            {
                Type = SecurityEventType.Maintenance,
                Title = "系统清理完成", Detail = StatusText,
            });
            CleanItems.Clear();
            SelectedBytes = 0;
        }
        catch (Exception ex)
        {
            StatusText = "清理失败：" + ex.Message;
            Serilog.Log.Error(ex, "清理失败");
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task AnalyzeDiskAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        try
        {
            DiskItems.Clear();
            var drive = Environment.SystemDirectory[..3];
            var items = await _maintenance.AnalyzeDiskSpaceAsync(drive);
            foreach (var i in items.Take(30)) DiskItems.Add(i);
            DiskAnalysisText = $"已分析 {drive} 顶层目录空间占用（大目录可能耗时较长）。";
        }
        catch (Exception ex)
        {
            DiskAnalysisText = "分析失败：" + ex.Message;
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task RunSfcAsync()
    {
        var ok = await _dialogs.ConfirmAsync("系统文件完整性检查 (SFC)",
            "将以管理员身份运行 sfc /verifyonly（只检查不修复，约 5-20 分钟）。需要您在 UAC 弹窗中确认。", "开始检查");
        if (!ok) return;
        IsBusy = true;
        SfcOutput = "SFC 检查中，请稍候…（此过程可能较长）";
        try
        {
            var r = await _maintenance.RunSfcVerifyAsync();
            SfcOutput = r.Success ? r.Output : "执行失败：\n" + r.Output;
            _repo.Insert(new MaintenanceRunRecord
            {
                Action = "SFC verifyonly", Detail = r.Success ? "完成" : "失败",
                Success = r.Success, StartedAt = DateTime.Now, FinishedAt = DateTime.Now,
            });
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task RunDismAsync()
    {
        var ok = await _dialogs.ConfirmAsync("DISM 系统映像检查",
            "将以管理员身份运行 DISM /Online /Cleanup-Image /ScanHealth（只检查不修复，约 5-15 分钟）。", "开始检查");
        if (!ok) return;
        IsBusy = true;
        DismOutput = "DISM 检查中，请稍候…";
        try
        {
            var r = await _maintenance.RunDismScanHealthAsync();
            DismOutput = r.Success ? r.Output : "执行失败：\n" + r.Output;
            _repo.Insert(new MaintenanceRunRecord
            {
                Action = "DISM ScanHealth", Detail = r.Success ? "完成" : "失败",
                Success = r.Success, StartedAt = DateTime.Now, FinishedAt = DateTime.Now,
            });
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task RunChkdskAsync()
    {
        var drive = Environment.SystemDirectory[..2];
        var ok = await _dialogs.ConfirmAsync("磁盘错误检查",
            $"将以管理员身份对 {drive} 运行只读 chkdsk 检查（不修复，不锁定卷）。", "开始检查");
        if (!ok) return;
        IsBusy = true;
        ChkOutput = "chkdsk 检查中…";
        try
        {
            var r = await _maintenance.RunChkdskReadOnlyAsync(drive);
            ChkOutput = r.Success ? r.Output : "执行失败：\n" + r.Output;
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task LoadRestorePointsAsync()
    {
        IsBusy = true;
        try
        {
            var pts = await _maintenance.GetRestorePointsAsync();
            RestorePoints.Clear();
            foreach (var p in pts) RestorePoints.Add(p);
            RestorePointsText = pts.Count > 0
                ? $"共 {pts.Count} 个还原点（读取该列表需要系统已开启系统还原）"
                : "未读取到还原点：可能系统还原未开启、需要管理员权限，或本机未创建过还原点。";
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task CreateRestorePointAsync()
    {
        var r = await _dialogs.PromptAsync("创建系统还原点",
            "输入还原点描述（将以管理员身份执行 Checkpoint-Computer）", "PSC 手动还原点 " + DateTime.Now.ToString("MM-dd HH:mm"));
        if (!r.ok) return;
        IsBusy = true;
        try
        {
            var result = await _maintenance.CreateRestorePointAsync(string.IsNullOrWhiteSpace(r.input) ? "PSC 手动还原点" : r.input);
            await _dialogs.InfoAsync("创建还原点", result.Success
                ? "还原点创建成功（若系统提示频率限制，请 1440 分钟内已创建过还原点时稍后再试）。"
                : "创建失败：" + result.Output);
            await LoadRestorePointsAsync();
        }
        finally { IsBusy = false; }
    }
}

/// <summary>启动项 + 软件管理页共用 VM。</summary>
public partial class StartupSoftwareViewModel : ObservableObject
{
    private readonly IStartupManager _startup;
    private readonly IInstalledAppsProvider _apps;
    private readonly WindowsTasksAndServices _tasksServices;
    private readonly IDialogService _dialogs;
    private readonly ISecurityEventService _events;

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _statusText = "";

    public ObservableCollection<StartupItem> StartupItems { get; } = new();
    public ObservableCollection<InstalledAppInfo> Apps { get; } = new();
    public ObservableCollection<ScheduledTaskInfo> Tasks { get; } = new();
    public ObservableCollection<ServiceInfo> Services { get; } = new();

    public StartupSoftwareViewModel(IStartupManager startup, IInstalledAppsProvider apps,
        WindowsTasksAndServices tasksServices, IDialogService dialogs, ISecurityEventService events)
    {
        _startup = startup;
        _apps = apps;
        _tasksServices = tasksServices;
        _dialogs = dialogs;
        _events = events;
        _ = LoadStartupAsync();
    }

    [RelayCommand]
    private async Task LoadStartupAsync()
    {
        IsBusy = true;
        try
        {
            var items = await _startup.EnumerateAsync();
            StartupItems.Clear();
            foreach (var i in items) StartupItems.Add(i);
            StatusText = $"共 {items.Count} 个启动项（注册表 + 启动文件夹）。";
        }
        catch (Exception ex) { StatusText = "加载失败：" + ex.Message; }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task ToggleStartupAsync(object? param)
    {
        if (param is not StartupItem item) return;
        var ok = await _dialogs.ConfirmAsync("修改启动项",
            $"{(item.Enabled ? "禁用" : "启用")}启动项：{item.Name}\n命令：{item.Command}\n\n" +
            (item.Enabled ? "禁用方式：注册表值改名（可随时恢复），不删除任何数据。" : "恢复为原名称。"),
            item.Enabled ? "禁用" : "启用", danger: item.Enabled);
        if (!ok) return;
        var success = await _startup.SetEnabledAsync(item, !item.Enabled);
        if (success)
        {
            await _events.PublishAsync(new SecurityEvent
            {
                Type = SecurityEventType.SystemModification,
                Severity = ThreatSeverity.Medium,
                Title = $"启动项已{(item.Enabled ? "禁用" : "启用")}",
                Detail = $"{item.Name}（{item.Location}）",
            });
            await LoadStartupAsync();
        }
        else
        {
            await _dialogs.InfoAsync("修改启动项", "操作失败：可能需要管理员权限（HKLM 启动项），或文件已被占用。");
        }
    }

    [RelayCommand]
    private async Task LoadAppsAsync()
    {
        IsBusy = true;
        try
        {
            var apps = await _apps.EnumerateAsync();
            Apps.Clear();
            foreach (var a in apps) Apps.Add(a);
            StatusText = $"共 {apps.Count} 个已安装软件。点击「打开卸载入口」将启动官方卸载程序。";
        }
        catch (Exception ex) { StatusText = "加载失败：" + ex.Message; }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task UninstallAppAsync(object? param)
    {
        if (param is not InstalledAppInfo app) return;
        var ok = await _dialogs.ConfirmAsync("打开卸载入口",
            $"软件：{app.DisplayName}\n发布者：{app.Publisher}\n\n将启动该软件的官方卸载程序（非静默卸载），请在弹出的向导中确认操作。",
            "打开卸载程序", danger: true);
        if (!ok) return;
        var success = PcSecurityCenter.Platform.Software.AppUninstaller.LaunchUninstall(app);
        if (!success) await _dialogs.InfoAsync("卸载", "无法启动卸载程序（未找到卸载入口）。可到 设置→应用 中手动卸载。");
    }

    [RelayCommand]
    private async Task LoadTasksAsync()
    {
        IsBusy = true;
        try
        {
            var tasks = await _tasksServices.GetScheduledTasksAsync();
            Tasks.Clear();
            foreach (var t in tasks) Tasks.Add(t);
            StatusText = $"共 {tasks.Count} 个非微软计划任务。";
        }
        catch (Exception ex) { StatusText = "加载失败：" + ex.Message; }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task ToggleTaskAsync(object? param)
    {
        if (param is not ScheduledTaskInfo t) return;
        var enable = !t.Enabled;
        var ok = await _dialogs.ConfirmAsync((enable ? "启用" : "禁用") + "计划任务",
            $"任务：{t.Path}{t.Name}\n动作：{t.Action}\n\n将以管理员权限执行官方 cmdlet（UAC 确认）。",
            enable ? "启用" : "禁用", danger: !enable);
        if (!ok) return;
        var op = enable ? ElevatedOperation.EnableScheduledTask : ElevatedOperation.DisableScheduledTask;
        var r = await new WindowsPermissionServiceProxy().Run(op, new Dictionary<string, string>
        {
            ["taskpath"] = t.Path,
            ["taskname"] = t.Name,
            ["enable"] = enable ? "1" : "0",
        });
        await _dialogs.InfoAsync("计划任务", r.Success ? "操作成功。" : "操作失败：" + r.Output);
        await LoadTasksAsync();
    }

    [RelayCommand]
    private async Task LoadServicesAsync()
    {
        IsBusy = true;
        try
        {
            var svcs = await _tasksServices.GetServicesAsync();
            Services.Clear();
            foreach (var s in svcs) Services.Add(s);
            StatusText = $"共 {svcs.Count} 个系统服务（默认只读展示）。";
        }
        catch (Exception ex) { StatusText = "加载失败：" + ex.Message; }
        finally { IsBusy = false; }
    }

    /// <summary>绕过 DI 的轻量代理（提权服务为单例，也可通过注入获取）。</summary>
    private sealed class WindowsPermissionServiceProxy
    {
        public Task<(bool Success, string Output)> Run(ElevatedOperation op, IReadOnlyDictionary<string, string> args)
            => new PcSecurityCenter.Platform.Security.WindowsPermissionService().RunElevatedAsync(op, args);
    }
}

/// <summary>高级工具页。</summary>
public partial class AdvancedToolsViewModel : ObservableObject
{
    private readonly INetworkMonitor _network;
    private readonly IPerformanceMonitor _performance;
    private readonly WindowsTasksAndServices _tasksServices;
    private readonly IDialogService _dialogs;

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _statusText = "";
    [ObservableProperty] private string _envVarsText = "";
    [ObservableProperty] private string _powerPlanText = "";
    [ObservableProperty] private string _systemInfoText = "";

    public ObservableCollection<ServiceInfo> Services { get; } = new();
    public ObservableCollection<NetworkAdapterInfo> Adapters { get; } = new();

    public AdvancedToolsViewModel(INetworkMonitor network, IPerformanceMonitor performance,
        WindowsTasksAndServices tasksServices, IDialogService dialogs)
    {
        _network = network;
        _performance = performance;
        _tasksServices = tasksServices;
        _dialogs = dialogs;
    }

    [RelayCommand]
    private async Task LoadSystemInfoAsync()
    {
        IsBusy = true;
        try
        {
            var hw = await _performance.GetHardwareInfoAsync();
            SystemInfoText =
                $"主机名：{hw.MachineName}\n操作系统：{hw.OsName}\n版本：{hw.OsVersion}（Build {hw.OsBuild}）\n" +
                $"64 位系统：{(hw.Is64Bit ? "是" : "否")}\nCPU：{hw.CpuName}\n内存总量：{PcSecurityCenter.Core.Utils.SizeFormat.Format((long)hw.MemoryTotalBytes)}\n" +
                $"GPU：{string.Join("；", hw.GpuNames)}\n上次启动：{hw.BootTime:yyyy-MM-dd HH:mm:ss}\n" +
                string.Join("\n", hw.Disks.Select(d => $"磁盘 {d.DriveLetter} {d.Model}：总 {PcSecurityCenter.Core.Utils.SizeFormat.Format((long)d.TotalBytes)}，剩余 {PcSecurityCenter.Core.Utils.SizeFormat.Format((long)d.FreeBytes)}"));
        }
        catch (Exception ex) { SystemInfoText = "读取失败：" + ex.Message; }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task LoadEnvVarsAsync()
    {
        IsBusy = true;
        try
        {
            var lines = new List<string> { "—— 用户环境变量 ——" };
            foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables(EnvironmentVariableTarget.User))
                lines.Add($"  {e.Key} = {e.Value}");
            lines.Add("—— 系统环境变量 ——" );
            foreach (System.Collections.DictionaryEntry e in Environment.GetEnvironmentVariables(EnvironmentVariableTarget.Machine))
                lines.Add($"  {e.Key} = {e.Value}");
            EnvVarsText = string.Join('\n', lines);
        }
        catch (Exception ex) { EnvVarsText = "读取失败：" + ex.Message; }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task LoadPowerPlansAsync()
    {
        IsBusy = true;
        try
        {
            using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("powercfg", "/list")
            {
                CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true,
            });
            var output = await p!.StandardOutput.ReadToEndAsync();
            p.WaitForExit(10_000);
            PowerPlanText = output;
        }
        catch (Exception ex) { PowerPlanText = "读取失败：" + ex.Message; }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task LoadServicesAsync()
    {
        IsBusy = true;
        try
        {
            var svcs = await _tasksServices.GetServicesAsync();
            Services.Clear();
            foreach (var s in svcs) Services.Add(s);
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task LoadAdaptersAsync()
    {
        IsBusy = true;
        try
        {
            var adapters = await _network.GetAdaptersAsync();
            Adapters.Clear();
            foreach (var a in adapters) Adapters.Add(a);
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task OpenPrivacySettingsAsync()
    {
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("ms-settings:privacy") { UseShellExecute = true }); }
        catch (Exception ex) { await _dialogs.InfoAsync("隐私设置", "无法打开：" + ex.Message); }
        await Task.CompletedTask;
    }
}
