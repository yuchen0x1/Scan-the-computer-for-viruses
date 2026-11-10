using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Data.Repositories;
using PcSecurityCenter.App.Services;
using PcSecurityCenter.Core.Reporting;

namespace PcSecurityCenter.App.ViewModels;

/// <summary>文件分析页。</summary>
public partial class FileAnalysisViewModel : ObservableObject
{
    private readonly IFileAnalysisService _analysis;
    private readonly IDefenderClient _defender;
    private readonly IConfigService _config;
    private readonly IDialogService _dialogs;

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _filePath = "";
    [ObservableProperty] private string _resultText = "";
    [ObservableProperty] private string _hashConsentNote =
        "隐私说明：本页分析全部在本机完成，不会上传任何文件内容或哈希。" +
        "「哈希信誉查询」为可选功能，默认关闭；如需启用，请在设置中心配置 API Key 并明确同意后再使用。";
    [ObservableProperty] private string _eicarNote =
        "提示：可通过下方按钮生成 EICAR 标准测试文件（全球通用的无害病毒测试样本，仅用于验证 Defender 引擎是否正常工作）。" +
        "生成后请立即用「对文件执行 Defender 扫描」验证，验证完成请删除该测试文件。";

    public FileAnalysisViewModel(IFileAnalysisService analysis, IDefenderClient defender,
        IConfigService config, IDialogService dialogs)
    {
        _analysis = analysis;
        _defender = defender;
        _config = config;
        _dialogs = dialogs;
    }

    [RelayCommand]
    private async Task BrowseAsync()
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Title = "选择要分析的文件" };
        if (dlg.ShowDialog() == true)
        {
            FilePath = dlg.FileName;
            await AnalyzeAsync();
        }
    }

    [RelayCommand]
    private async Task AnalyzeAsync()
    {
        if (IsBusy) return;
        if (string.IsNullOrWhiteSpace(FilePath) || !File.Exists(FilePath))
        {
            await _dialogs.InfoAsync("文件分析", "请先选择存在的文件。");
            return;
        }
        IsBusy = true;
        try
        {
            var report = await _analysis.AnalyzeAsync(FilePath);
            ResultText =
                $"文件：{report.FilePath}\n大小：{PcSecurityCenter.Core.Utils.SizeFormat.Format(report.SizeBytes)}\n类型：{report.FileTypeName}\n" +
                $"创建时间：{report.CreatedAt:yyyy-MM-dd HH:mm:ss}\n修改时间：{report.ModifiedAt:yyyy-MM-dd HH:mm:ss}\n\n" +
                $"SHA256：{report.Sha256}\nSHA1：{report.Sha1}\nMD5：{report.Md5}\n\n" +
                $"内容熵：{report.EntropyBitsPerByte:F2} bits/byte（>7.2 通常意味着加壳/压缩/加密内容，仅提示）\n" +
                $"PE 文件：{(report.IsPe ? $"是（{report.PeMachine}）" : "否")}\n" +
                $"数字签名：{(report.PeIsSigned == null ? "未验证" : report.PeIsSigned == true ? $"有效（{report.SignatureSubject}）" : $"无效或缺失（{report.SignatureStatus}）")}\n" +
                (report.IsPe && report.Indicators.Count > 0 ? "\n可疑指标：\n  " + string.Join("\n  ", report.Indicators) + "\n" : "") +
                $"\n风险评估：{report.RiskLevel} —— {report.RiskSummary}";
        }
        catch (Exception ex)
        {
            ResultText = "分析失败：" + ex.Message;
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task DefenderScanFileAsync()
    {
        if (string.IsNullOrWhiteSpace(FilePath) || !File.Exists(FilePath))
        {
            await _dialogs.InfoAsync("Defender 扫描", "请先选择存在的文件。");
            return;
        }
        IsBusy = true;
        try
        {
            var r = await _defender.ScanPathsAsync(new[] { FilePath }, CancellationToken.None);
            await _dialogs.InfoAsync("Defender 扫描结果",
                r.Success
                    ? (r.ThreatsFound > 0
                        ? $"Defender 检出 {r.ThreatsFound} 个威胁：\n{string.Join("\n", r.ThreatList)}\n\n请到「病毒查杀」页查看并处理（Defender 记录已同步）。"
                        : "Defender 引擎未发现威胁（ExitCode 0）。注意：引擎结论仅代表当前病毒库能力。")
                    : "扫描执行失败：" + r.Error);
            // 同步最新威胁记录
            var dets = await _defender.GetThreatDetectionsAsync();
            foreach (var d in dets.Where(d => d.FilePath.Equals(FilePath, StringComparison.OrdinalIgnoreCase)))
                Serilog.Log.Information("Defender 检出 {File}: {Name}", d.FilePath, d.Name);
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task GenerateEicarAsync()
    {
        var ok = await _dialogs.ConfirmAsync("生成 EICAR 测试文件",
            "将在桌面生成 eicar_test.txt（含 EICAR 标准测试字符串）。\n\n" +
            "这是全球杀毒行业通用的无害测试样本，用于验证 Defender 实时防护/扫描功能是否正常。\n" +
            "开启实时防护时 Defender 可能立即自动隔离该文件——这正是引擎正常工作的证明。\n\n继续？",
            "生成", danger: false);
        if (!ok) return;
        try
        {
            const string eicar = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            var path = Path.Combine(desktop, "eicar_test.txt");
            await File.WriteAllTextAsync(path, eicar);
            FilePath = path;
            await _dialogs.InfoAsync("EICAR 测试文件", $"已生成：{path}\n\n如实时防护已开启，Defender 会自动检出并隔离它（正常现象）。也可点击「对文件执行 Defender 扫描」手动验证。验证完成后请删除该测试文件。");
        }
        catch (Exception ex)
        {
            await _dialogs.InfoAsync("EICAR 测试文件", "生成失败（可能被实时防护拦截——这本身也说明引擎工作正常）：" + ex.Message);
        }
    }
}

/// <summary>安全报告中心页。</summary>
public partial class ReportCenterViewModel : ObservableObject
{
    private readonly ScanRunRepository _scans;
    private readonly ThreatRepository _threats;
    private readonly SecurityEventRepository _events;
    private readonly CheckResultRepository _checks;
    private readonly MaintenanceRunRepository _maintenance;
    private readonly IPerformanceMonitor _performance;
    private readonly IScoreCalculator _score;
    private readonly IDialogService _dialogs;

    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _statusText = "选择导出格式生成完整安全报告。";

    public ObservableCollection<ScanRunRecord> Scans { get; } = new();
    public ObservableCollection<SecurityEvent> Events { get; } = new();
    public ObservableCollection<MaintenanceRunRecord> MaintenanceRuns { get; } = new();

    public ReportCenterViewModel(ScanRunRepository scans, ThreatRepository threats, SecurityEventRepository events,
        CheckResultRepository checks, MaintenanceRunRepository maintenance, IPerformanceMonitor performance,
        IScoreCalculator score, IDialogService dialogs)
    {
        _scans = scans;
        _threats = threats;
        _events = events;
        _checks = checks;
        _maintenance = maintenance;
        _performance = performance;
        _score = score;
        _dialogs = dialogs;
        _ = LoadAsync();
    }

    private async Task LoadAsync()
    {
        try
        {
            Scans.Clear();
            foreach (var s in _scans.GetRecent(50)) Scans.Add(s);
            Events.Clear();
            foreach (var e in _events.GetRecent(60)) Events.Add(e);
            MaintenanceRuns.Clear();
            foreach (var m in _maintenance.GetRecent(50)) MaintenanceRuns.Add(m);
        }
        catch (Exception) { }
        await Task.CompletedTask;
    }

    private Task<ReportData> BuildReportDataAsync() => Task.Run(async () =>
    {
        // 全部数据采集（WMI/DriveInfo/SQLite）都放到线程池，
        // 避免点击导出时 UI 线程同步等待导致界面冻结数秒。
        var hw = await _performance.GetHardwareInfoAsync().ConfigureAwait(false);
        var checks = _checks.GetLatestRun();
        return new ReportData
        {
            MachineName = hw.MachineName,
            OsName = $"{hw.OsName}（Build {hw.OsBuild}）",
            Score = checks.Count > 0 ? _score.FromChecks(checks) : null,
            Checks = checks,
            Scans = _scans.GetRecent(100),
            Threats = _threats.GetRecent(200),
            Events = _events.GetRecent(100),
            MaintenanceRuns = _maintenance.GetRecent(100),
        };
    });

    [RelayCommand]
    private async Task ExportHtmlAsync()
    {
        IsBusy = true;
        try
        {
            var data = await BuildReportDataAsync();
            var file = Path.Combine(PcSecurityCenter.Data.Configuration.AppPaths.ReportsDir,
                $"security-report_{DateTime.Now:yyyyMMdd_HHmmss}.html");
            await File.WriteAllTextAsync(file, HtmlReportBuilder.Build(data));
            StatusText = "HTML 报告已导出：" + file;
            var open = await _dialogs.ConfirmAsync("导出成功", "HTML 报告已生成。是否立即在浏览器中打开？", "打开");
            if (open) System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(file) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            StatusText = "导出失败：" + ex.Message;
            Serilog.Log.Error(ex, "HTML 报告导出失败");
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task ExportPdfAsync()
    {
        IsBusy = true;
        try
        {
            var data = await BuildReportDataAsync();
            var file = Path.Combine(PcSecurityCenter.Data.Configuration.AppPaths.ReportsDir,
                $"security-report_{DateTime.Now:yyyyMMdd_HHmmss}.pdf");
            await Task.Run(() => PdfReportExporter.Export(data, file));
            StatusText = "PDF 报告已导出：" + file;
            var open = await _dialogs.ConfirmAsync("导出成功", "PDF 报告已生成。是否立即打开？", "打开");
            if (open) System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(file) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            StatusText = "PDF 导出失败：" + ex.Message;
            Serilog.Log.Error(ex, "PDF 报告导出失败");
        }
        finally { IsBusy = false; }
    }

    [RelayCommand]
    private async Task OpenReportsDirAsync()
    {
        try { System.Diagnostics.Process.Start("explorer.exe", PcSecurityCenter.Data.Configuration.AppPaths.ReportsDir); } catch (Exception) { }
        await Task.CompletedTask;
    }
}

/// <summary>设置中心页。</summary>
public partial class SettingsViewModel : ObservableObject
{
    private readonly IConfigService _config;
    private readonly IDialogService _dialogs;
    private readonly IRealtimeProtector _protector;
    private readonly IPerformanceMonitor _performance;

    [ObservableProperty] private int _performanceIntervalMs;
    [ObservableProperty] private int _realtimePollSec;
    [ObservableProperty] private bool _realtimeEnabled;
    [ObservableProperty] private bool _autoUpdateSignatures;
    [ObservableProperty] private bool _hashLookupEnabled;
    [ObservableProperty] private string _hashLookupApiKey = "";
    [ObservableProperty] private string _statusText = "";
    [ObservableProperty] private string _dataDirText;

    /// <summary>true=亮色（白天，默认）；false=暗色。切换立即生效并持久化。</summary>
    [ObservableProperty] private bool _useLightTheme = true;

    public string ThemeSummary => UseLightTheme
        ? "当前：亮色（白天模式），下次启动保持亮色"
        : "当前：暗色（夜间模式），下次启动保持暗色";

    public SettingsViewModel(IConfigService config, IDialogService dialogs, IRealtimeProtector protector, IPerformanceMonitor performance)
    {
        _config = config;
        _dialogs = dialogs;
        _protector = protector;
        _performance = performance;
        PerformanceIntervalMs = config.Current.PerformanceIntervalMs;
        RealtimePollSec = config.Current.RealtimePollIntervalSec;
        RealtimeEnabled = config.Current.RealtimeEnabled;
        AutoUpdateSignatures = config.Current.AutoUpdateDefenderSignatures;
        HashLookupEnabled = config.Current.HashLookupEnabled;
        HashLookupApiKey = config.Current.HashLookupApiKey ?? "";
        DataDirText = PcSecurityCenter.Data.Configuration.AppPaths.DataRoot;
        UseLightTheme = config.Current.UseLightTheme;
    }

    partial void OnUseLightThemeChanged(bool value) => OnPropertyChanged(nameof(ThemeSummary));

    /// <summary>切换主题：立即应用 + 写入配置，无需重启。</summary>
    [RelayCommand]
    private async Task ApplyThemeAsync()
    {
        PcSecurityCenter.App.Services.ThemeService.Apply(UseLightTheme);
        _config.Current.UseLightTheme = UseLightTheme;
        await _config.SaveAsync();
        StatusText = $"已切换为{(UseLightTheme ? "亮色（白天）" : "暗色（夜间）")}模式，下次启动将保持该选择。";
    }

    [RelayCommand]
    private async Task SaveAsync()
    {
        var c = _config.Current;
        c.PerformanceIntervalMs = Math.Clamp(PerformanceIntervalMs, 500, 60_000);
        c.RealtimePollIntervalSec = Math.Clamp(RealtimePollSec, 5, 300);
        c.RealtimeEnabled = RealtimeEnabled;
        c.AutoUpdateDefenderSignatures = AutoUpdateSignatures;
        c.HashLookupEnabled = HashLookupEnabled;
        c.HashLookupApiKey = string.IsNullOrWhiteSpace(HashLookupApiKey) ? null : HashLookupApiKey.Trim();
        c.UseLightTheme = UseLightTheme;
        await _config.SaveAsync();
        _performance.SetIntervalMs(c.PerformanceIntervalMs);
        PcSecurityCenter.App.Services.ThemeService.Apply(c.UseLightTheme);
        StatusText = "设置已保存。部分设置在重启实时防护后完全生效。";
    }

    [RelayCommand]
    private async Task OpenLogsAsync()
    {
        try { System.Diagnostics.Process.Start("explorer.exe", PcSecurityCenter.Data.Configuration.AppPaths.LogsDir); } catch (Exception) { }
        await Task.CompletedTask;
    }

    [RelayCommand]
    private async Task OpenDataDirAsync()
    {
        try { System.Diagnostics.Process.Start("explorer.exe", PcSecurityCenter.Data.Configuration.AppPaths.DataRoot); } catch (Exception) { }
        await Task.CompletedTask;
    }

    [RelayCommand]
    private async Task AboutAsync()
    {
        await _dialogs.InfoAsync("关于",
            "Windows 智能安全卫士 (PC Security Center) v" +
            (typeof(SettingsViewModel).Assembly.GetName().Version?.ToString(3) ?? "1.2.0") + "\n\n" +
            "检测能力说明（如实声明）：\n" +
            "· 病毒检测依赖 Microsoft Defender 官方引擎与病毒库，本工具提供调度、结果展示与威胁处理；\n" +
            "· 智能风险引擎基于公开规则做可疑行为提示，不构成病毒判定；\n" +
            "· 本工具不保证检测所有威胁，评分仅反映本工具定义检查项的量化结果；\n" +
            "· 所有数据保留在本机，不做任何上传。\n\n" +
            "第三方组件许可：.NET 10 (MIT)、CommunityToolkit.Mvvm (MIT)、Serilog (Apache 2.0)、\n" +
            "LiveCharts2 (MIT)、QuestPDF（社区许可）、SQLite (Public Domain)。");
    }
}
