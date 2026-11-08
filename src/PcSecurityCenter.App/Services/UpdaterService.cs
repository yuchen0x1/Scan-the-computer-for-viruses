using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using PcSecurityCenter.Core.Update;
using PcSecurityCenter.Platform.Security;

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
    // 下载走独立 HttpClient：大文件流式读取由下方分阶段超时控制，不能被 20s 全局超时掐断。
    private readonly HttpClient _downloadHttp = new() { Timeout = Timeout.InfiniteTimeSpan };
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
    /// <summary>下载完成并通过校验的安装包 SHA256（应用前会再次比对防替换）。</summary>
    public string? VerifiedSha256 { get; private set; }
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

    /// <summary>下载安装包到临时目录，并做完整性校验：文件名净化、下载源限定 GitHub 官方主机、
    /// 字节数核对、SHA256 与发布附带校验和比对、Authenticode 签名策略。全部通过后状态变为 Ready。</summary>
    public async Task DownloadAsync(CancellationToken cancellationToken = default)
    {
        if (LatestRelease?.SetupAsset is not { } asset)
        {
            LastError = "未找到可用的安装包资源";
            State = UpdateState.Error;
            return;
        }

        if (asset.SafeFileName() is not { } fileName)
        {
            LastError = "安装包资源文件名非法";
            State = UpdateState.Error;
            return;
        }

        if (!IsTrustedDownloadHost(asset.DownloadUrl))
        {
            LastError = "安装包下载地址不在可信主机上";
            State = UpdateState.Error;
            return;
        }

        State = UpdateState.Downloading;
        DownloadProgressPercent = 0;
        DownloadProgressChanged?.Invoke(this, 0);
        try
        {
            Directory.CreateDirectory(_downloadDir);
            var dest = Path.Combine(_downloadDir, fileName);
            var part = dest + ".part";

            long read;
            string sha256;
            using (var headCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                // 分阶段超时：连接+响应头 30s，之后流式读取每 60s 必须有进展，避免大文件被整体超时掐断。
                headCts.CancelAfter(TimeSpan.FromSeconds(30));
                using var resp = await _downloadHttp.GetAsync(
                    asset.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, headCts.Token);
                resp.EnsureSuccessStatusCode();
                var total = resp.Content.Headers.ContentLength ?? asset.Size;

                await using var src = await resp.Content.ReadAsStreamAsync(cancellationToken);
                await using var fs = File.Create(part);
                using var hasher = SHA256.Create();
                var buffer = new byte[81920];
                read = 0;
                int n;
                using var idleCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                while (true)
                {
                    idleCts.CancelAfter(TimeSpan.FromSeconds(60));
                    n = await src.ReadAsync(buffer, idleCts.Token);
                    if (n <= 0) break;
                    await fs.WriteAsync(buffer.AsMemory(0, n), cancellationToken);
                    hasher.TransformBlock(buffer, 0, n, null, 0);
                    read += n;
                    if (total > 0)
                    {
                        DownloadProgressPercent = (int)(read * 100 / total);
                        DownloadProgressChanged?.Invoke(this, DownloadProgressPercent);
                    }
                }
                hasher.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                sha256 = Convert.ToHexString(hasher.Hash!).ToLowerInvariant();
            }

            if (asset.Size > 0 && read != asset.Size)
                throw new InvalidDataException($"下载不完整：期望 {asset.Size} 字节，实际 {read} 字节");

            await VerifyDownloadedPackageAsync(fileName, part, sha256, cancellationToken);

            File.Move(part, dest, overwrite: true);
            DownloadedPath = dest;
            VerifiedSha256 = sha256;
            State = UpdateState.Ready;
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            State = UpdateState.Error;
            Serilog.Log.Warning(ex, "更新包下载失败");
        }
    }

    /// <summary>
    /// 校验已下载的安装包：发布附带 SHA256SUMS 时哈希必须匹配；
    /// 有 Authenticode 签名时必须验证通过；既无签名又无校验和则拒绝安装。
    /// </summary>
    private async Task VerifyDownloadedPackageAsync(
        string fileName, string filePath, string sha256, CancellationToken cancellationToken)
    {
        var hasChecksum = false;
        if (LatestRelease?.ChecksumsAsset is { } sums)
        {
            if (!IsTrustedDownloadHost(sums.DownloadUrl))
                throw new InvalidDataException("校验和文件下载地址不在可信主机上");
            using var headCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            headCts.CancelAfter(TimeSpan.FromSeconds(30));
            var text = await _downloadHttp.GetStringAsync(sums.DownloadUrl, headCts.Token);
            var map = ChecksumFile.Parse(text);
            if (!map.TryGetValue(fileName, out var expected))
                throw new InvalidDataException("校验和文件中没有该安装包的记录");
            if (!string.Equals(expected, sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("SHA256 校验失败，安装包可能已损坏或被篡改");
            hasChecksum = true;
        }

        var sig = SignatureVerifier.Verify(filePath, checkRevocation: true);
        if (sig.IsSigned && !sig.IsValid)
            throw new InvalidDataException("安装包数字签名验证失败：" + sig.StatusText);
        if (!sig.IsSigned && !hasChecksum)
            throw new InvalidDataException("安装包既无有效数字签名也无校验和，拒绝安装");
    }

    private static bool IsTrustedDownloadHost(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var u)
           && u.Scheme == Uri.UriSchemeHttps
           && (u.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase)
               || u.Host.EndsWith(".githubusercontent.com", StringComparison.OrdinalIgnoreCase));

    /// <summary>运行已下载的安装包（静默模式）并退出当前进程，由安装程序替换文件后重启新版本。
    /// 运行前重新比对 SHA256，防止校验后被替换。</summary>
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
            if (VerifiedSha256 is { } expected)
            {
                using var fs = File.OpenRead(DownloadedPath);
                var actual = Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
                if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
                {
                    LastError = "安装包在校验后被修改，已中止更新";
                    State = UpdateState.Error;
                    return;
                }
            }

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
