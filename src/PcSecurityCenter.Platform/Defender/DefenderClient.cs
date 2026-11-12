using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Platform.PowerShell;

namespace PcSecurityCenter.Platform.Defender;

/// <summary>
/// Microsoft Defender 官方接口客户端。
/// 全部通过 Windows PowerShell 5.1 官方 cmdlet（Get-MpComputerStatus / Start-MpScan /
/// Get-MpThreatDetection / Remove-MpThreat / Update-MpSignature / MSFT_MpScan WMI）
/// 与官方命令行工具 MpCmdRun.exe 实现，无任何逆向或非公开接口。
/// </summary>
public class DefenderClient : IDefenderClient
{
    private readonly object _gate = new();
    private Task<bool>? _probeTask;
    private bool? _available;
    // 状态短缓存：Defender 状态不会秒级变化，避免每次进入页面都 spawn 一个 powershell.exe
    private DefenderStatusInfo? _statusCache;
    private DateTime _statusCacheAt;
    private static readonly TimeSpan StatusCacheTtl = TimeSpan.FromSeconds(8);

    /// <summary>探测结果缓存后的同步读取。已探测过则零成本；未探测时会阻塞等待一次异步探测。</summary>
    public bool IsAvailable
    {
        get
        {
            if (_available == null) _available = IsAvailableAsync().GetAwaiter().GetResult();
            return _available.Value;
        }
    }

    /// <summary>异步获取 Defender 可用性（探测只执行一次，结果复用）。</summary>
    public Task<bool> IsAvailableAsync()
    {
        lock (_gate)
        {
            return _probeTask ??= ProbeAsync();
        }
    }

    public string? MpCmdRunPath { get; } = LocateMpCmdRun();

    private static string? LocateMpCmdRun()
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Microsoft Defender Antivirus", "MpCmdRun.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Windows Defender", "MpCmdRun.exe"),
        };
        return candidates.FirstOrDefault(File.Exists);
    }

    private async Task<bool> ProbeAsync()
    {
        try
        {
            var r = await PowerShellRunner.RunAsync(
                "$s = Get-MpComputerStatus -ErrorAction Stop; @{ok=([bool]$s.AMServiceEnabled -and [bool]$s.AntivirusEnabled)} | ConvertTo-Json -Compress",
                timeoutMs: 45_000);
            var ok = r.Success && r.Json is { ValueKind: JsonValueKind.Object } j &&
                     j.TryGetProperty("ok", out var value) && value.ValueKind == JsonValueKind.True;
            Serilog.Log.Information("Defender 可用性探测完成：{Result}", ok);
            return ok;
        }
        catch (Exception ex)
        {
            Serilog.Log.Warning(ex, "Defender 可用性探测失败");
            return false;
        }
    }

    /// <summary>用已经拿到的状态填充可用性缓存，避免重复探测。</summary>
    private void SeedAvailability(bool value)
    {
        lock (_gate)
        {
            _available = value;
            _probeTask ??= Task.FromResult(value);
        }
    }

    public async Task<DefenderStatusInfo> GetStatusAsync(CancellationToken ct = default)
    {
        // 短 TTL 缓存：连续进入多个页面不会重复 spawn powershell.exe
        lock (_gate)
        {
            if (_statusCache != null && DateTime.UtcNow - _statusCacheAt < StatusCacheTtl)
                return _statusCache;
        }

        var info = new DefenderStatusInfo();
        const string script = """
$ErrorActionPreference = 'Stop'
try {
  $s = Get-MpComputerStatus -ErrorAction Stop
  @{ ok = $true
     rt  = $s.RealTimeProtectionEnabled
     av  = $s.AntivirusEnabled
     am  = $s.AMServiceEnabled
     bm  = $s.BehaviorMonitorEnabled
     sigTime = $s.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm:ss')
     sigVer  = $s.AntivirusSignatureVersion
     quickEnd = if ($s.QuickScanEndTime) { $s.QuickScanEndTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
     fullEnd  = if ($s.FullScanEndTime) { $s.FullScanEndTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
  } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; err = $_.Exception.Message } | ConvertTo-Json -Compress
}
""";
        var r = await PowerShellRunner.RunAsync(script, timeoutMs: 45_000, ct: ct);
        var j = r.JsonFromTag("ok") is { ValueKind: JsonValueKind.Object } o ? o : r.Json;
        if (j.ValueKind != JsonValueKind.Object)
        {
            info.ErrorNote = "无法读取 Defender 状态（接口调用失败或未安装）。";
            return info;
        }
        bool Get(string n) => j.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.True;
        info.Installed = true;
        info.EngineAvailable = Get("ok");
        info.RealTimeProtection = Get("rt");
        info.AntivirusEnabled = Get("av");
        info.EngineAvailable &= Get("am");
        info.BehaviorMonitor = Get("bm");
        if (j.TryGetProperty("sigTime", out var st) && st.ValueKind == JsonValueKind.String && DateUtil.TryParse(st.GetString(), out var dt))
            info.SignatureLastUpdated = dt;
        if (j.TryGetProperty("sigVer", out var sv) && sv.ValueKind == JsonValueKind.String)
            info.SignatureVersion = sv.GetString() ?? string.Empty;
        if (j.TryGetProperty("quickEnd", out var qe) && DateUtil.TryParse(qe.GetString(), out var qd))
            info.LastQuickScan = qd;
        if (j.TryGetProperty("fullEnd", out var fe) && DateUtil.TryParse(fe.GetString(), out var fd))
            info.LastFullScan = fd;
        if (info.LastQuickScan != null)
            info.QuickScanAgeDays = (int)(DateTime.Now - info.LastQuickScan.Value).TotalDays;
        if (!info.EngineAvailable)
            info.ErrorNote = "Defender 服务存在但引擎状态异常。";

        SeedAvailability(info.Installed && info.EngineAvailable);
        lock (_gate)
        {
            _statusCache = info;
            _statusCacheAt = DateTime.UtcNow;
        }
        return info;
    }

    public async Task<bool> UpdateSignaturesAsync(CancellationToken ct = default)
    {
        const string script = """
try { Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction Stop; 'OK' } catch { $_.Exception.Message }
""";
        var r = await PowerShellRunner.RunAsync(script, timeoutMs: 300_000, ct: ct);
        return r.Success && r.StdOut.Contains("OK");
    }

    public async Task<bool> StartQuickScanAsync(CancellationToken ct = default)
    {
        // Start-MpScan 为同步阻塞调用；放在独立进程中执行，完成后自然返回
        const string script = """
try { Start-MpScan -ScanType QuickScan -ErrorAction Stop; 'SCANDONE' } catch { 'SCANFAIL: ' + $_.Exception.Message }
""";
        var r = await PowerShellRunner.RunAsync(script, timeoutMs: 30 * 60_000, ct: ct);
        return r.StdOut.Contains("SCANDONE");
    }

    /// <summary>
    /// 按 ThreatID 定点处理一条 Defender 威胁（隔离/清除）。
    ///
    /// 安全要点：不带 -ThreatID 的 Remove-MpThreat 会清除**全部**活动威胁，
    /// 相当于用户在列表里点一条记录却清空了整台机器的检测记录。因此这里强制要求
    /// 合法的威胁 ID，任何非数字输入都在进入脚本前被拒绝。
    /// </summary>
    public async Task<bool> RemoveThreatAsync(long threatId, CancellationToken ct = default)
    {
        if (threatId <= 0) return false;

        const string script = """
$tidText = $env:PSC_THREATID
$tid = [int64]0
if (-not [int64]::TryParse($tidText, [ref]$tid)) { 'FAIL: 非法的威胁 ID'; exit 0 }
try {
  Remove-MpThreat -ThreatID $tid -ErrorAction Stop
  'REMOVED'
} catch { 'FAIL: ' + $_.Exception.Message }
""";
        var r = await PowerShellRunner.RunAsync(script,
            new Dictionary<string, string> { ["threatid"] = threatId.ToString() },
            timeoutMs: 300_000, ct: ct);
        return r.StdOut.Contains("REMOVED");
    }

    // ---------------- MpCmdRun 定向扫描 ----------------
    public async Task<MpScanResult> ScanPathsAsync(IEnumerable<string> paths, CancellationToken ct)
    {
        var result = new MpScanResult();
        if (MpCmdRunPath == null)
        {
            result.Error = "MpCmdRun.exe 不可用";
            return result;
        }
        foreach (var path in paths)
        {
            ct.ThrowIfCancellationRequested();
            var one = await RunMpCmdRunScanAsync(path, ct);
            result.ExitCode = one.ExitCode;
            result.ThreatsFound += one.ThreatsFound;
            result.ThreatList.AddRange(one.ThreatList);
            result.RawOutputTail = one.RawOutputTail;
            result.Success = one.Success;
            if (!one.Success) result.Error = one.Error;
        }
        return result;
    }

    private async Task<MpScanResult> RunMpCmdRunScanAsync(string path, CancellationToken ct)
    {
        var result = new MpScanResult();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = MpCmdRunPath!,
                // 参数固定为官方开关；路径作为独立参数传入（ProcessStartInfo.ArgumentList 天然防注入）
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
            };
            psi.ArgumentList.Add("-Scan");
            psi.ArgumentList.Add("-ScanType");
            psi.ArgumentList.Add("3");
            psi.ArgumentList.Add("-File");
            psi.ArgumentList.Add(path);
            psi.ArgumentList.Add("-DisableRemediation");

            using var proc = Process.Start(psi)!;
            var output = new StringBuilder();
            proc.OutputDataReceived += (_, e) => { if (e.Data != null) { lock (output) output.AppendLine(e.Data); } };
            proc.ErrorDataReceived += (_, e) => { };
            proc.BeginOutputReadLine();

            using var reg = ct.Register(() => { try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); } catch (Exception) { } });
            await proc.WaitForExitAsync(ct);
            string stdout;
            lock (output) stdout = output.ToString();
            result.ExitCode = proc.ExitCode;
            result.RawOutputTail = string.Join('\n', stdout.Split('\n').Where(l => l.Contains("found", StringComparison.OrdinalIgnoreCase) || l.Contains("威胁", StringComparison.Ordinal)).Take(10));
            // MpCmdRun 结束语："<N> threat(s) found" 或 "no threats found"
            var m = System.Text.RegularExpressions.Regex.Match(stdout, @"(\d+)\s+threats?\s+found", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (m.Success && int.TryParse(m.Groups[1].Value, out var n)) result.ThreatsFound = n;
            result.Success = result.ExitCode == 0;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }
        return result;
    }

    // ---------------- 流式逐目录扫描（全盘） ----------------
    private const string StreamScript = """
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Test-Admin { (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
while ($true) {
  $line = [Console]::In.ReadLine()
  if ($null -eq $line) { break }
  if ($line -eq '__EXIT__') { break }
  $t0 = Get-Date
  $ok = $true; $err = ''
  try { Start-MpScan -ScanType CustomScan -ScanPath $line -ErrorAction Stop } catch { $ok = $false; $err = $_.Exception.Message }
  $files = 0
  try {
    if (Test-Path -LiteralPath $line -PathType Leaf) { $files = 1 }
    else { $files = @(Get-ChildItem -LiteralPath $line -Recurse -File -Force -ErrorAction SilentlyContinue).Count }
  } catch { }
  $dets = @()
  try {
    $dets = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $t0 })
  } catch { }
  $out = @{ dir = $line; ok = $ok; err = $err; files = $files; sec = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1); dets = @() }
  foreach ($d in $dets) {
    $res = @()
    try { $res = @($d.Resources | ForEach-Object { $_ }) } catch { }
    $out.dets += ,@{ tid = [int64]$d.ThreatID; time = $d.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm:ss'); res = $res }
  }
  $out | ConvertTo-Json -Compress -Depth 4
}
""";

    public async IAsyncEnumerable<DirectoryScanResult> StreamScanDirectoriesAsync(
        ChannelReader<string> directories, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        if (!IsAvailable) yield break;

        var psi = new ProcessStartInfo
        {
            FileName = PowerShellRunnerPsExe,
            Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + PowerShellRunner.Encode(StreamScript),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        var threatNames = await LoadThreatNameMapAsync(ct);

        using var proc = new Process { StartInfo = psi };
        proc.Start();

        // 读取通道：后台任务把 stdout 行送入 channel
        var lineChannel = Channel.CreateBounded<string>(new BoundedChannelOptions(64)
        {
            SingleReader = true,
            FullMode = BoundedChannelFullMode.Wait,
        });

        var reader = Task.Run(async () =>
        {
            try
            {
                while (await proc.StandardOutput.ReadLineAsync().ConfigureAwait(false) is { } line)
                    await lineChannel.Writer.WriteAsync(line, ct).ConfigureAwait(false);
            }
            catch (Exception) { }
            finally { lineChannel.Writer.TryComplete(); }
        }, ct);

        // 喂目录：通道数据 → stdin（写入端阻塞即引擎空闲，从而支持暂停）
        var feeder = Task.Run(async () =>
        {
            try
            {
                await foreach (var dir in directories.ReadAllAsync(ct).ConfigureAwait(false))
                {
                    await proc.StandardInput.WriteLineAsync(dir).ConfigureAwait(false);
                    await proc.StandardInput.FlushAsync().ConfigureAwait(false);
                }
                await proc.StandardInput.WriteLineAsync("__EXIT__").ConfigureAwait(false);
                await proc.StandardInput.FlushAsync().ConfigureAwait(false);
            }
            catch (Exception) { try { proc.StandardInput.Close(); } catch { } }
        }, ct);

        // 停止时终止引擎进程
        using var reg = ct.Register(() => { try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); } catch (Exception) { } });

        try
        {
            await foreach (var line in lineChannel.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var r = ParseDirectoryScanLine(line, threatNames);
                if (r != null) yield return r;
            }
        }
        finally
        {
            try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); } catch (Exception) { }
        }
    }

    private static string PowerShellRunnerPsExe => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");

    private DirectoryScanResult? ParseDirectoryScanLine(string line, Dictionary<long, string> threatNames)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            var r = new DirectoryScanResult
            {
                Directory = root.GetProperty("dir").GetString() ?? string.Empty,
                Success = root.GetProperty("ok").GetBoolean(),
                FileCount = root.TryGetProperty("files", out var f) && f.ValueKind == JsonValueKind.Number ? f.GetInt32() : 0,
                Seconds = root.TryGetProperty("sec", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetDouble() : 0,
                Error = root.TryGetProperty("err", out var e) ? e.GetString() ?? string.Empty : string.Empty,
            };
            if (root.TryGetProperty("dets", out var dets) && dets.ValueKind == JsonValueKind.Array)
            {
                foreach (var d in dets.EnumerateArray())
                {
                    var tid = d.TryGetProperty("tid", out var t) && t.ValueKind == JsonValueKind.Number ? t.GetInt64() : 0;
                    threatNames.TryGetValue(tid, out var tname);
                    var resources = new List<string>();
                    if (d.TryGetProperty("res", out var resArr) && resArr.ValueKind == JsonValueKind.Array)
                        foreach (var rr in resArr.EnumerateArray())
                        {
                            var p = ResourceToPath(rr.GetString());
                            if (!string.IsNullOrEmpty(p)) resources.Add(p);
                        }
                    var time = d.TryGetProperty("time", out var tt) && DateUtil.TryParse(tt.GetString(), out var dt) ? dt : DateTime.Now;
                    if (resources.Count == 0)
                        resources.Add(r.Directory);
                    foreach (var res in resources)
                    {
                        r.NewDetections.Add(new ThreatInfo
                        {
                            Name = string.IsNullOrEmpty(tname) ? $"Defender 威胁 ID {tid}" : tname,
                            Severity = ThreatSeverity.High,
                            Kind = DetectionKind.Confirmed,
                            FilePath = res,
                            Engine = "MicrosoftDefender",
                            Evidence = $"Microsoft Defender 官方引擎检出（ThreatID={tid}，检测时间 {time:yyyy-MM-dd HH:mm:ss}）",
                            DefenderThreatId = tid,
                            Recommendation = "建议使用隔离处理；Defender 威胁可通过官方接口清除。",
                        });
                    }
                }
            }
            return r;
        }
        catch (JsonException) { return null; }
    }

    private static string? ResourceToPath(string? resource)
    {
        if (string.IsNullOrEmpty(resource)) return null;
        // Defender Resources 格式：file:_C:\xxx 或 file:C:\xxx 或 regkey:...
        if (resource.StartsWith("file:_", StringComparison.OrdinalIgnoreCase)) return resource[6..];
        if (resource.StartsWith("file:", StringComparison.OrdinalIgnoreCase)) return resource[5..];
        return null;
    }

    private async Task<Dictionary<long, string>> LoadThreatNameMapAsync(CancellationToken ct)
    {
        var map = new Dictionary<long, string>();
        const string script = """
try { @(Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { @{ id = [int64]$_.ThreatID; name = $_.ThreatName; sev = [int]$_.SeverityID } }) | ConvertTo-Json -Compress -Depth 3 } catch { '[]' }
""";
        var r = await PowerShellRunner.RunAsync(script, timeoutMs: 60_000, ct: ct);
        try
        {
            using var doc = JsonDocument.Parse(r.StdOut.Trim());
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
                foreach (var t in doc.RootElement.EnumerateArray())
                {
                    var id = t.GetProperty("id").GetInt64();
                    map[id] = t.GetProperty("name").GetString() ?? string.Empty;
                }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                var id = doc.RootElement.GetProperty("id").GetInt64();
                map[id] = doc.RootElement.GetProperty("name").GetString() ?? string.Empty;
            }
        }
        catch (Exception) { }
        return map;
    }

    // ---------------- 威胁检测记录 ----------------
    public async Task<List<ThreatInfo>> GetThreatDetectionsAsync(CancellationToken ct = default)
    {
        const string script = """
$map = @{}
try { Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $map[[int64]$_.ThreatID] = @{ name = $_.ThreatName; sev = [int]$_.SeverityID } } } catch { }
$cut = (Get-Date).AddDays(-30)
$out = @()
try {
  Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -ge $cut } | ForEach-Object {
    $tid = [int64]$_.ThreatID
    $name = ''; $sev = 2
    if ($map.ContainsKey($tid)) { $name = $map[$tid].name; $sev = $map[$tid].sev }
    $res = @($_.Resources | ForEach-Object { $_ })
    @{ tid = $tid; name = $name; sev = $sev; time = $_.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm:ss'); res = $res; active = $false } | ConvertTo-Json -Compress -Depth 4
  }
} catch { }
""";
        var list = new List<ThreatInfo>();
        var r = await PowerShellRunner.RunAsync(script, timeoutMs: 90_000, ct: ct);
        foreach (var line in r.StdOut.Split('\n'))
        {
            var t = line.Trim();
            if (!t.StartsWith('{')) continue;
            try
            {
                using var doc = JsonDocument.Parse(t);
                var o = doc.RootElement;
                var tid = o.GetProperty("tid").GetInt64();
                var name = o.GetProperty("name").GetString() ?? $"Defender 威胁 ID {tid}";
                var sev = o.GetProperty("sev").GetInt32();
                var time = DateUtil.TryParse(o.GetProperty("time").GetString(), out var dt) ? dt : DateTime.Now;
                foreach (var res in o.GetProperty("res").EnumerateArray())
                {
                    var p = ResourceToPath(res.GetString());
                    if (string.IsNullOrEmpty(p)) continue;
                    list.Add(new ThreatInfo
                    {
                        Name = name,
                        Severity = MapSeverity(sev),
                        Kind = DetectionKind.Confirmed,
                        FilePath = p,
                        Engine = "MicrosoftDefender",
                        Evidence = $"Microsoft Defender 官方威胁检测记录（ThreatID={tid}，首次检测 {time:yyyy-MM-dd HH:mm:ss}）",
                        DetectedAt = time,
                        DefenderThreatId = tid,
                        Recommendation = "建议在威胁处理页执行隔离/清除（Defender 官方接口）。",
                    });
                }
            }
            catch (Exception) { }
        }
        return list.GroupBy(x => x.FilePath).Select(g => g.First()).ToList();
    }

    private static ThreatSeverity MapSeverity(int defenderSev) => defenderSev switch
    {
        >= 4 => ThreatSeverity.Critical,
        3 => ThreatSeverity.High,
        2 => ThreatSeverity.Medium,
        1 => ThreatSeverity.Low,
        _ => ThreatSeverity.Info,
    };
}

/// <summary>PS5.1 日期字符串解析（yyyy-MM-dd HH:mm:ss）。</summary>
public static class DateUtil
{
    public static bool TryParse(string? s, out DateTime dt)
    {
        dt = default;
        return !string.IsNullOrWhiteSpace(s) && DateTime.TryParse(s, out dt);
    }
}
