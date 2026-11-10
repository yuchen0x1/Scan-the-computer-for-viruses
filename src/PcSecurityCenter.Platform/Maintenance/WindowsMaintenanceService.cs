using System.Diagnostics;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Core.Scanning;
using PcSecurityCenter.Core.Utils;

namespace PcSecurityCenter.Platform.Maintenance;

/// <summary>
/// 系统维护服务。清理项采用白名单目录 + 逐文件安全规则：
/// 只删除普通文件（跳过目录、跳过使用中、跳过系统关键路径），从不递归删除目录根。
/// SFC/DISM/chkdsk/还原点通过受控提权执行（用户确认 + 日志）。
/// </summary>
public class WindowsMaintenanceService : IMaintenanceService
{
    private readonly IPermissionService _permission;

    public WindowsMaintenanceService(IPermissionService permission) => _permission = permission;

    // ---------------- 可清理项扫描 ----------------
    public Task<List<MaintenanceCleanItem>> ScanCleanableAsync(CancellationToken ct = default) => Task.Run(async () =>
    {
        var items = new List<MaintenanceCleanItem>();

        void AddItem(string id, string name, string desc, string dir, bool recursive, bool requiresAdmin = false, int olderThanDays = 0)
        {
            long size = 0; int count = 0; var samples = new List<string>();
            try
            {
                if (!Directory.Exists(dir)) return;
                var cutoff = olderThanDays > 0 ? DateTime.Now.AddDays(-olderThanDays) : DateTime.MinValue;
                foreach (var f in FileEnumerator.EnumerateFiles(dir, ct))
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        var fi = new FileInfo(f);
                        if (olderThanDays > 0 && fi.LastWriteTime > cutoff) continue;
                        size += fi.Length;
                        count++;
                        if (samples.Count < 5) samples.Add(fi.FullName);
                    }
                    catch (Exception) { }
                    if (count > 200_000) break; // 安全上限
                }
                if (count == 0) return;
                items.Add(new MaintenanceCleanItem
                {
                    Id = id, Name = name, Description = desc + $"（目录：{dir}）",
                    SizeBytes = size, FileCount = count, SampleFiles = samples, RequiresAdmin = requiresAdmin,
                });
            }
            catch (Exception) { }
        }

        AddItem("user-temp", "用户临时文件", "当前用户 %TEMP% 目录中 7 天前的临时文件",
            Path.GetTempPath(), recursive: true, olderThanDays: 7);
        AddItem("user-localappdata-temp", "LocalAppData 临时目录", "应用本地临时文件",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            recursive: true, olderThanDays: 7);
        AddItem("windows-temp", "系统临时文件", "C:\\Windows\\Temp 中 7 天前的临时文件（需管理员）",
            @"C:\Windows\Temp", recursive: true, requiresAdmin: true, olderThanDays: 7);
        AddItem("prefetch", "预读取缓存", "Windows 预读取缓存（删除后短期影响启动速度，自动重建）",
            @"C:\Windows\Prefetch", recursive: false, requiresAdmin: true, olderThanDays: 30);
        AddItem("dump", "内存转储与错误报告", "系统错误转储文件（MEMORY.DMP、Minidump、WER 报告）",
            @"C:\Windows\Minidump", recursive: false, requiresAdmin: true);
        AddItem("wer", "Windows 错误报告队列", "已提交与排队的错误报告文件",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Microsoft\Windows\WER\ReportQueue"), recursive: true);
        AddItem("update-cache", "Windows 更新下载缓存", "SoftwareDistribution\\Download 中已下载的更新包（需管理员）",
            @"C:\Windows\SoftwareDistribution\Download", recursive: true, requiresAdmin: true, olderThanDays: 14);

        // 回收站（通过 Shell 读取大小）
        var rb = await ScanRecycleBinAsync(ct).ConfigureAwait(false);
        if (rb != null) items.Add(rb);

        return items;
    }, ct);

    private async Task<MaintenanceCleanItem?> ScanRecycleBinAsync(CancellationToken ct)
    {
        try
        {
            const string script = """
$shell = New-Object -ComObject Shell.Application
$rb = $shell.Namespace(0xA)
$size = 0; $count = 0
if ($rb) {
  foreach ($i in $rb.Items()) {
    try { $sz = $i.Size; if ($sz) { $size += [long]$sz; $count++ } } catch { }
  }
}
@{ size = $size; count = $count } | ConvertTo-Json -Compress
""";
            var r = await PowerShellRunnerProxy.RunAsync(script, 30_000).ConfigureAwait(false);
            if (r == null) return null;
            var item = new MaintenanceCleanItem
            {
                Id = "recycle-bin",
                Name = "回收站",
                Description = "清空回收站（所有分区）。删除后无法恢复，请先确认。",
                SizeBytes = r.Value.size,
                FileCount = r.Value.count,
            };
            return item.FileCount > 0 || item.SizeBytes > 0 ? item : null;
        }
        catch (Exception) { return null; }
    }

    private static class PowerShellRunnerProxy
    {
        public static async Task<(long size, int count)?> RunAsync(string script, int timeoutMs)
        {
            var r = await PcSecurityCenter.Platform.PowerShell.PowerShellRunner
                .RunAsync(script, timeoutMs: timeoutMs).ConfigureAwait(false);
            try
            {
                var j = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(r.StdOut.Trim());
                return ((long)j.GetProperty("size").GetInt64(), j.GetProperty("count").GetInt32());
            }
            catch (Exception) { return null; }
        }
    }

    // ---------------- 执行清理 ----------------
    public async Task<(long FreedBytes, int FilesRemoved)> CleanAsync(IEnumerable<MaintenanceCleanItem> items, CancellationToken ct = default)
    {
        long freed = 0; int removed = 0;
        var selected = items.ToList();

        // Never trust the UI description as an executable path. Rebuild every
        // deletion target from a narrow service-owned ID allowlist and reapply
        // the same age policy used by the preview.
        foreach (var item in selected.Where(i => !i.RequiresAdmin && i.Id != "recycle-bin"))
        {
            var target = GetCleanTarget(item.Id);
            if (target == null || !Directory.Exists(target.Value.Directory)) continue;
            var cutoff = target.Value.OlderThanDays > 0
                ? DateTime.Now.AddDays(-target.Value.OlderThanDays)
                : DateTime.MinValue;
            var (f, n) = CleanDirectoryFiles(target.Value.Directory, cutoff, ct);
            freed += f; removed += n;
        }

        // 回收站
        if (selected.Any(i => i.Id == "recycle-bin"))
        {
            const string script = "try { Clear-RecycleBin -Force -ErrorAction Stop; 'RB_OK' } catch { 'RB_FAIL: ' + $_.Exception.Message }";
            var r = await PcSecurityCenter.Platform.PowerShell.PowerShellRunner.RunAsync(script, timeoutMs: 120_000, ct: ct);
            if (r.StdOut.Contains("RB_OK")) removed++;
        }

        // 需要管理员的项目：提示（UI 层引导提权流程）
        if (selected.Any(i => i.RequiresAdmin))
        {
            Serilog.Log.Information("存在需要管理员权限的清理项，由 UI 引导用户提权执行");
        }
        return (freed, removed);
    }

    /// <summary>逐文件清理：只删普通文件，跳过使用中/系统/只读可疑文件；不删除目录本身。</summary>
    private static (string Directory, int OlderThanDays)? GetCleanTarget(string id) => id switch
    {
        "user-temp" => (Path.GetTempPath(), 7),
        "user-localappdata-temp" => (Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"), 7),
        "wer" => (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "Windows", "WER", "ReportQueue"), 0),
        _ => null,
    };

    private static (long freed, int removed) CleanDirectoryFiles(string dir, DateTime cutoff, CancellationToken ct)
    {
        long freed = 0; int removed = 0;
        foreach (var f in FileEnumerator.EnumerateFiles(dir, ct))
        {
            ct.ThrowIfCancellationRequested();
            if (!PathSafety.IsSafeToDelete(f)) continue;
            try
            {
                var fi = new FileInfo(f);
                if (fi.LastWriteTime > cutoff) continue;
                // 跳过使用中的文件
                using (var s = fi.Open(FileMode.Open, FileAccess.ReadWrite, FileShare.None)) { }
                var size = fi.Length;
                fi.Delete();
                freed += size; removed++;
            }
            catch (IOException) { }      // 使用中
            catch (UnauthorizedAccessException) { } // 无权限
            catch (Exception) { }
        }
        Serilog.Log.Information("清理目录 {Dir}：删除 {N} 个文件，释放 {Bytes}", dir, removed, freed);
        return (freed, removed);
    }

    // ---------------- 磁盘空间分析 ----------------
    public Task<List<DiskSpaceItem>> AnalyzeDiskSpaceAsync(string driveRoot, CancellationToken ct = default) => Task.Run(() =>
    {
        var list = new List<DiskSpaceItem>();
        try
        {
            foreach (var sub in Directory.EnumerateDirectories(driveRoot))
            {
                ct.ThrowIfCancellationRequested();
                long size = 0; int files = 0;
                foreach (var f in FileEnumerator.EnumerateFiles(sub, CancellationToken.None))
                {
                    try { size += new FileInfo(f).Length; files++; }
                    catch (Exception) { }
                    if (files > 500_000) break;
                }
                list.Add(new DiskSpaceItem { Path = sub, SizeBytes = size, FileCount = files });
            }
            list.Add(new DiskSpaceItem
            {
                Path = driveRoot,
                SizeBytes = list.Sum(x => x.SizeBytes),
                FileCount = list.Sum(x => x.FileCount),
            });
        }
        catch (Exception) { }
        return list.OrderByDescending(x => x.SizeBytes).ToList();
    }, ct);

    // ---------------- SFC / DISM / chkdsk（提权） ----------------
    public Task<(bool Success, string Output)> RunSfcVerifyAsync(CancellationToken ct = default) =>
        _permission.RunElevatedAsync(ElevatedOperation.RunSfcVerifyOnly, ct: ct);

    public Task<(bool Success, string Output)> RunDismScanHealthAsync(CancellationToken ct = default) =>
        _permission.RunElevatedAsync(ElevatedOperation.RunDismScanHealth, ct: ct);

    public Task<(bool Success, string Output)> RunChkdskReadOnlyAsync(string drive, CancellationToken ct = default) =>
        _permission.RunElevatedAsync(ElevatedOperation.RunChkdskReadOnly,
            new Dictionary<string, string> { ["drive"] = drive }, ct);

    // ---------------- 还原点 ----------------
    public async Task<List<RestorePointInfo>> GetRestorePointsAsync(CancellationToken ct = default)
    {
        const string script = """
try {
  Get-ComputerRestorePoint -ErrorAction Stop | ForEach-Object {
    @{ seq = $_.SequenceNumber; desc = $_.Description; time = $_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss'); type = $_.RestorePointType }
  } | ConvertTo-Json -Compress
} catch {
  @{ err = $_.Exception.Message } | ConvertTo-Json -Compress
}
""";
        var r = await PcSecurityCenter.Platform.PowerShell.PowerShellRunner.RunAsync(script, timeoutMs: 60_000, ct: ct);
        var list = new List<RestorePointInfo>();
        var t = r.StdOut.Trim();
        if (t.Contains("\"err\"")) return list; // 权限不足或未开启：返回空列表由 UI 说明
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(t);
            if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Array)
                foreach (var p in doc.RootElement.EnumerateArray())
                    list.Add(new RestorePointInfo
                    {
                        SequenceNumber = p.GetProperty("seq").GetInt32(),
                        Description = p.GetProperty("desc").GetString() ?? "",
                        CreationTime = DateTime.Parse(p.GetProperty("time").GetString() ?? ""),
                        Type = p.GetProperty("type").GetString() ?? "",
                    });
            else if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object)
                list.Add(new RestorePointInfo
                {
                    SequenceNumber = doc.RootElement.GetProperty("seq").GetInt32(),
                    Description = doc.RootElement.GetProperty("desc").GetString() ?? "",
                    CreationTime = DateTime.Parse(doc.RootElement.GetProperty("time").GetString() ?? ""),
                    Type = doc.RootElement.GetProperty("type").GetString() ?? "",
                });
        }
        catch (Exception) { }
        return list;
    }

    public Task<(bool Success, string Output)> CreateRestorePointAsync(string description, CancellationToken ct = default) =>
        _permission.RunElevatedAsync(ElevatedOperation.CreateRestorePoint,
            new Dictionary<string, string> { ["desc"] = description }, ct);
}
