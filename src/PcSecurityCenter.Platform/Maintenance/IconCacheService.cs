using System.Diagnostics;
using PcSecurityCenter.Core.Abstractions;

namespace PcSecurityCenter.Platform.Maintenance;

/// <summary>
/// 图标缓存文件路径与白名单（纯逻辑，便于单元测试）。
/// Windows 的图标缓存固定为两处：旧版单文件 IconCache.db 与 Explorer 目录下的 iconcache_*.db 分库。
/// 任何删除操作都必须先通过 <see cref="IsIconCacheFile"/> 白名单校验，防止清理范围外溢。
/// </summary>
public static class IconCachePaths
{
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    /// <summary>旧版（Win7 时代）单文件图标缓存。</summary>
    public static string LegacyCacheFile => Path.Combine(LocalAppData, "IconCache.db");

    /// <summary>Vista+ 图标/缩略图缓存分库目录。</summary>
    public static string ExplorerCacheDir => Path.Combine(LocalAppData, "Microsoft", "Windows", "Explorer");

    /// <summary>白名单校验：仅接受两个已知缓存目录内的 iconcache 数据库文件，其余一律拒绝。</summary>
    public static bool IsIconCacheFile(string path, string? localAppDataBase = null)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        string full;
        try { full = Path.GetFullPath(path); } catch (Exception) { return false; }

        var baseDir = localAppDataBase ?? LocalAppData;
        var name = Path.GetFileName(full);
        var dir = Path.GetDirectoryName(full);
        if (dir is null) return false;

        // 旧版缓存：LocalAppData 根下的单个 IconCache.db（精确名称匹配）
        if (dir.Equals(baseDir, StringComparison.OrdinalIgnoreCase)
            && name.Equals("IconCache.db", StringComparison.OrdinalIgnoreCase))
            return true;

        // 新版缓存：Explorer 目录下 iconcache 开头的 .db 分库
        if (dir.Equals(Path.Combine(baseDir, "Microsoft", "Windows", "Explorer"), StringComparison.OrdinalIgnoreCase)
            && name.StartsWith("iconcache", StringComparison.OrdinalIgnoreCase)
            && name.EndsWith(".db", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    /// <summary>枚举当前实际存在的图标缓存文件（每个结果都已通过白名单校验）。</summary>
    public static List<FileInfo> EnumerateCacheFiles()
    {
        var result = new List<FileInfo>();
        void TryAdd(string path)
        {
            if (!IsIconCacheFile(path)) return;
            try
            {
                var fi = new FileInfo(path);
                if (fi.Exists) result.Add(fi);
            }
            catch (Exception) { }
        }
        TryAdd(LegacyCacheFile);
        try
        {
            if (Directory.Exists(ExplorerCacheDir))
                foreach (var f in Directory.EnumerateFiles(ExplorerCacheDir, "iconcache_*.db"))
                    TryAdd(f);
        }
        catch (Exception) { }
        return result;
    }
}

/// <summary>图标缓存重建的默认实现：关闭 Explorer → 白名单删除缓存 → 自动重启 Explorer。
/// 全程不需要管理员权限（缓存位于当前用户目录，Explorer 属于当前会话）。</summary>
public class IconCacheService : IIconCacheService
{
    public Task<(bool Success, string Output)> RebuildAsync(CancellationToken ct = default) => Task.Run(() =>
    {
        var log = new List<string>();
        try
        {
            // 1. 枚举缓存文件（白名单）
            var files = IconCachePaths.EnumerateCacheFiles();
            if (files.Count == 0)
                return (true, "未发现图标缓存数据库文件，无需重建。若图标仍异常，请重启电脑后重试。");

            var totalKb = files.Sum(f => f.Length) / 1024.0;
            log.Add($"发现 {files.Count} 个缓存文件，共 {totalKb:F1} KB");

            // 2. 结束 Explorer（桌面与任务栏短暂消失属正常现象）
            foreach (var p in Process.GetProcessesByName("explorer"))
            {
                try { p.Kill(); log.Add($"已结束 Explorer（PID {p.Id}）"); }
                catch (Exception ex) { log.Add($"结束 Explorer（PID {p.Id}）失败：{ex.Message}"); }
                finally { try { p.Dispose(); } catch { } }
            }
            for (var i = 0; i < 20; i++)
            {
                if (Process.GetProcessesByName("explorer").Length == 0) break;
                Thread.Sleep(250);
            }

            // 3. 逐个删除缓存数据库（跳过仍被占用的文件，绝不扩大删除范围）
            var removed = 0;
            long freed = 0;
            foreach (var f in files)
            {
                try
                {
                    var size = f.Length;
                    f.Delete();
                    removed++;
                    freed += size;
                    log.Add($"已删除 {f.Name}");
                }
                catch (Exception ex) { log.Add($"跳过 {f.Name}（可能仍被占用）：{ex.Message}"); }
            }

            return (true, $"图标缓存重建完成：删除 {removed}/{files.Count} 个文件，释放 {freed / 1024.0:F1} KB。\n"
                          + string.Join("\n", log));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "重建图标缓存失败");
            return (false, "重建失败：" + ex.Message + "\n" + string.Join("\n", log));
        }
        finally
        {
            // 4. 无论成败，确保 Explorer 被重新拉起，绝不让用户停留在无壳状态
            try
            {
                if (Process.GetProcessesByName("explorer").Length == 0)
                {
                    Process.Start(new ProcessStartInfo("explorer.exe") { UseShellExecute = true });
                    log.Add("Explorer 已重新启动");
                }
            }
            catch (Exception ex) { Log.Error(ex, "重启 Explorer 失败，请手动 Ctrl+Shift+Esc 启动 explorer.exe"); }
        }
    }, ct);
}
