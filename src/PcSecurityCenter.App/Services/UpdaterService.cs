using System.Diagnostics;
using System.IO;
using System.Net.Http;
using PcSecurityCenter.Core.Update;

namespace PcSecurityCenter.App.Services;

/// <summary>更新状态机：驱动「检测 → 下载 → 应用（重启）」全流程。</summary>
public enum UpdateState
{
    Idle,        // 尚未开始
    Checking,    // 正在检测
    UpToDate,    // 已是最新
    Available,   // 检测到新版本（尚未下载）
    Downloading, // 正在下载安装包
    Ready,       // 安装包已下载，等待应用
    Applying,    // 正在应用（启动安装程序并退出）
    Error,       // 出错
}

public sealed class UpdateCheckResult
{
    public bool IsUpdateAvailable { get; init; }
    public ReleaseInfo? Latest { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// 内置自动更新器：每次启动时调用 <see cref="CheckAsync"/> 检测 GitHub Releases 上的新版本；
/// 若有新版本则 <see cref="DownloadAsync"/> 自动下载安装包，<see cref="ApplyAndRestart"/> 静默
/// 运行安装程序并退出当前进程以完成更新。所有网络操作均带超时与异常保护，绝不阻塞或拖垮启动流程。
/// </summary>
public sealed class UpdaterService
{
    // 公开仓库的 Releases API（无需鉴权；调用方机器需可访问 github.com）。
    private const string ApiLatest = "https://api.github.com/repos/yuchen0x1/Scan-the-computer-for-viruses/releases/latest";
    private const string ApiReleases = "https://api.github.com/repos/yuchen0x1/Scan-the-computer-for-viruses/releases?per_page=10";

    private readonly HttpClient _http;
    private readonly string _downloadDir;

    public Version CurrentVersion { get; }

    private UpdateState _state = UpdateState.Idle;
    public UpdateState State
    {
        get => _state;
        private set
        {
            if (_state == value) return;
            _state = value;
            StateChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public ReleaseInfo? LatestRelease { get; private set; }
    public string? LastError { get; private set; }
    public DateTime? LastChecked { get; private set; }
    public string? DownloadedPath { get; private set; }
    public int DownloadProgressPercent { get; private set; }

    public event EventHandler? StateChanged;
    public event EventHandler<int>? DownloadProgressChanged;

    public UpdaterService()
    {
        CurrentVersion = typeof(UpdaterService).Assembly.GetName().Version ?? new Version(1, 0, 0, 0);
        _downloadDir = Path.Combine(Path.GetTempPath(), "PcSecurityCenterUpdates");
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        // GitHub API 要求必须携带 User-Agent，否则返回 403。
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("PcSecurityCenter-App");
        _http.DefaultRequestHeaders.Accept.Add(
            new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
    }

    /// <summary>检测是否有新版本。网络异常时返回 IsUpdateAvailable=false 且不抛异常。</summary>
    public async Task<UpdateCheckResult> CheckAsync()
    {
        State = UpdateState.Checking;
        LastError = null;
        try
        {
            var json = await _http.GetStringAsync(ApiLatest);
            var releases = ReleaseParser.ParseReleases(json);
            var latest = releases.FirstOrDefault(r => !r.Draft && !r.Prerelease);
            LastChecked = DateTime.Now;
            if (latest is null)
            {
                State = UpdateState.UpToDate;
                return new UpdateCheckResult { IsUpdateAvailable = false };
            }

            var latestVer = VersionUtility.ParseVersion(latest.Version) ?? new Version(0, 0, 0, 0);
            var cmp = VersionUtility.Compare(CurrentVersion, latestVer);
            LatestRelease = latest;
            if (cmp < 0)
            {
                State = UpdateState.Available;
                return new UpdateCheckResult { IsUpdateAvailable = true, Latest = latest };
            }

            State = UpdateState.UpToDate;
            return new UpdateCheckResult { IsUpdateAvailable = false };
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            State = UpdateState.Error;
            Serilog.Log.Warning(ex, "更新检测失败");
            return new UpdateCheckResult { IsUpdateAvailable = false, Error = ex.Message };
        }
    }

    /// <summary>拉取最近的发布列表，用于「更新日志」展示（排除草稿与预发布）。</summary>
    public async Task<List<ReleaseInfo>> FetchReleasesAsync()
    {
        try
        {
            var json = await _http.GetStringAsync(ApiReleases);
            return ReleaseParser.ParseReleases(json)
                .Where(r => !r.Draft && !r.Prerelease)
                .ToList();
        }
        catch (Exception ex)
        {
            Serilog.Log.Warning(ex, "更新日志拉取失败");
            return new List<ReleaseInfo>();
        }
    }

    /// <summary>下载安装包到临时目录。完成后状态变为 Ready。</summary>
    public async Task DownloadAsync()
    {
        if (LatestRelease?.SetupAsset is not { } asset)
        {
            LastError = "未找到可用的安装包资源";
            State = UpdateState.Error;
            return;
        }

        State = UpdateState.Downloading;
        DownloadProgressPercent = 0;
        DownloadProgressChanged?.Invoke(this, 0);
        try
        {
            Directory.CreateDirectory(_downloadDir);
            var dest = Path.Combine(_downloadDir, asset.Name);
            using var resp = await _http.GetAsync(asset.DownloadUrl, HttpCompletionOption.ResponseHeadersRead);
            resp.EnsureSuccessStatusCode();
            var total = resp.Content.Headers.ContentLength ?? asset.Size;

            await using var src = await resp.Content.ReadAsStreamAsync();
            await using var fs = File.Create(dest);
            var buffer = new byte[81920];
            long read = 0;
            int n;
            while ((n = await src.ReadAsync(buffer)) > 0)
            {
                await fs.WriteAsync(buffer.AsMemory(0, n));
                read += n;
                if (total > 0)
                {
                    DownloadProgressPercent = (int)(read * 100 / total);
                    DownloadProgressChanged?.Invoke(this, DownloadProgressPercent);
                }
            }

            DownloadedPath = dest;
            State = UpdateState.Ready;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            State = UpdateState.Error;
            Serilog.Log.Warning(ex, "更新包下载失败");
        }
    }

    /// <summary>运行已下载的安装包（静默模式）并退出当前进程，由安装程序替换文件后重启新版本。</summary>
    public void ApplyAndRestart()
    {
        if (DownloadedPath is null || !File.Exists(DownloadedPath))
        {
            LastError = "更新包尚未下载完成";
            State = UpdateState.Error;
            return;
        }

        try
        {
            State = UpdateState.Applying;
            var psi = new ProcessStartInfo
            {
                FileName = DownloadedPath,
                // VERYSILENT：无界面；SUPPRESSMSGBOXES：不弹确认框；NORESTART：不重启系统（但会按 [Run] 重启应用）。
                Arguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
                UseShellExecute = true,
            };
            Process.Start(psi);
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            State = UpdateState.Error;
            Serilog.Log.Error(ex, "启动安装程序失败");
            return;
        }

        // 给安装程序一点时间独立起来，再退出当前进程，确保文件可被替换。
        Task.Delay(500).ContinueWith(_ =>
        {
            try { Environment.Exit(0); }
            catch { }
        });
    }
}
