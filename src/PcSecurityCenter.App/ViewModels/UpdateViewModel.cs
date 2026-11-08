using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PcSecurityCenter.App.Services;
using PcSecurityCenter.Core.Update;

namespace PcSecurityCenter.App.ViewModels;

/// <summary>更新日志条目（一个版本一条）。</summary>
public sealed record ChangelogEntry
{
    public string Version { get; init; } = "";
    public string DateText { get; init; } = "";
    public string Notes { get; init; } = "";
    public bool IsCurrent { get; init; }
}

/// <summary>
/// 更新中心 ViewModel：把「检测更新」与「更新日志」整合到同一入口。
/// 检测/下载/应用以 UpdaterService 为底层引擎；更新日志优先从 GitHub 拉取，
/// 离线时回退到随安装包分发的本地 更新日志.md。
/// </summary>
public partial class UpdateViewModel : ObservableObject
{
    private readonly UpdaterService _updater;

    [ObservableProperty] private string _currentVersionText = "";
    [ObservableProperty] private string _lastCheckedText = "尚未检查";
    [ObservableProperty] private string _statusText = "点击「检查更新」开始检测";
    [ObservableProperty] private int _downloadProgress;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private bool _isDownloading;
    [ObservableProperty] private bool _canCheck = true;
    [ObservableProperty] private bool _canDownload;
    [ObservableProperty] private bool _canApply;
    [ObservableProperty] private ObservableCollection<ChangelogEntry> _changelog = new();

    public UpdateViewModel(UpdaterService updater)
    {
        _updater = updater;
        CurrentVersionText = $"v{_updater.CurrentVersion.ToString(3)}";
        _updater.StateChanged += (_, _) => ReflectState();
        _updater.DownloadProgressChanged += (_, p) => DownloadProgress = p;
        ReflectState();
        _ = LoadChangelogAsync();
    }

    private void ReflectState()
    {
        var s = _updater.State;
        IsBusy = s is UpdateState.Checking or UpdateState.Downloading or UpdateState.Applying;
        IsDownloading = s == UpdateState.Downloading;
        CanCheck = !IsBusy;
        CanDownload = s == UpdateState.Available;
        CanApply = s == UpdateState.Ready;
        if (_updater.LastChecked is { } t)
            LastCheckedText = t.ToString("yyyy-MM-dd HH:mm");

        StatusText = s switch
        {
            UpdateState.Idle => "点击「检查更新」开始检测",
            UpdateState.Checking => "正在检测更新…",
            UpdateState.UpToDate => $"已是最新版本（v{_updater.CurrentVersion.ToString(3)}）",
            UpdateState.Available => $"发现新版本 v{_updater.LatestRelease?.Version}，可更新",
            UpdateState.Downloading => $"正在下载更新包… {DownloadProgress}%",
            UpdateState.Ready => "更新包已下载，点击「立即更新」重启以完成升级",
            UpdateState.Applying => "正在应用更新，应用即将重启…",
            UpdateState.Error => $"更新出错：{_updater.LastError ?? "未知错误"}",
            _ => StatusText,
        };
    }

    [RelayCommand]
    private async Task CheckAsync()
    {
        if (!CanCheck) return;
        var result = await _updater.CheckAsync();
        // 检测到新版本后自动开始下载，减少用户操作步骤。
        if (result.IsUpdateAvailable)
            await _updater.DownloadAsync();
    }

    [RelayCommand]
    private async Task DownloadAsync()
    {
        if (!CanDownload) return;
        await _updater.DownloadAsync();
    }

    [RelayCommand]
    private void Apply()
    {
        if (!CanApply) return;
        _updater.ApplyAndRestart();
    }

    [RelayCommand]
    private async Task RefreshChangelogAsync() => await LoadChangelogAsync();

    /// <summary>加载更新日志：优先 GitHub，失败回退本地 更新日志.md。</summary>
    public async Task LoadChangelogAsync()
    {
        var releases = await _updater.FetchReleasesAsync();
        if (releases.Count > 0)
        {
            var cur = _updater.CurrentVersion.ToString(3);
            Changelog = new ObservableCollection<ChangelogEntry>(releases.Select(r => new ChangelogEntry
            {
                Version = $"v{r.Version}",
                DateText = r.PublishedAt != default ? r.PublishedAt.ToString("yyyy-MM-dd") : "",
                Notes = CleanNotes(r.Notes),
                IsCurrent = r.Version == cur,
            }));
            return;
        }

        // 离线回退：解析本地随安装包提供的 更新日志.md。
        var local = LoadLocalChangelog();
        if (local.Count > 0)
            Changelog = new ObservableCollection<ChangelogEntry>(local);
    }

    private static string CleanNotes(string md)
    {
        if (string.IsNullOrWhiteSpace(md)) return "";
        var sb = new StringBuilder();
        foreach (var line in md.Replace("\r\n", "\n").Split('\n'))
        {
            var l = line.TrimEnd();
            if (l.StartsWith("#")) continue;        // 去掉标题行（已在卡片标题展示）
            sb.AppendLine(l);
        }
        return sb.ToString().Trim();
    }

    private List<ChangelogEntry> LoadLocalChangelog()
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "更新日志.md");
            if (!File.Exists(path)) return new List<ChangelogEntry>();
            var lines = File.ReadAllLines(path);
            var entries = new List<ChangelogEntry>();
            ChangelogEntry? current = null;
            var body = new List<string>();
            foreach (var raw in lines)
            {
                var line = raw.TrimEnd();
                if (line.StartsWith("## "))
                {
                    if (current is not null)
                    {
                        current = current with { Notes = string.Join("\n", body).Trim() };
                        entries.Add(current);
                    }
                    var header = line[3..].Trim();
                    var m = System.Text.RegularExpressions.Regex.Match(header, @"(\d+\.\d+\.\d+)\s*(\(([^)]*)\))?");
                    var ver = m.Success ? m.Groups[1].Value : header;
                    var date = m.Success && m.Groups[3].Success ? m.Groups[3].Value : "";
                    current = new ChangelogEntry { Version = $"v{ver}", DateText = date };
                    body.Clear();
                }
                else if (current is not null)
                {
                    body.Add(line);
                }
            }
            if (current is not null)
                entries.Add(current with { Notes = string.Join("\n", body).Trim() });
            return entries;
        }
        catch
        {
            return new List<ChangelogEntry>();
        }
    }
}
