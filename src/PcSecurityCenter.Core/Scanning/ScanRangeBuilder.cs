using PcSecurityCenter.Core.Abstractions;

namespace PcSecurityCenter.Core.Scanning;

/// <summary>
/// 扫描范围构建器。范围真实、可解释：快速扫描覆盖恶意软件最常见驻留位置；
/// 全盘扫描覆盖本地固定磁盘；扫描时排除系统独占的符号链接以避免循环。
/// </summary>
public class ScanRangeBuilder : IScanRangeBuilder
{
    public List<string> BuildQuickRange()
    {
        var roots = new List<string>();
        void AddExisting(string? p)
        {
            if (!string.IsNullOrWhiteSpace(p) && Directory.Exists(p)) roots.Add(p);
        }

        // Windows 启动相关目录
        AddExisting(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
        AddExisting(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
        AddExisting(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"));
        AddExisting(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks"));
        // 用户临时目录
        AddExisting(Path.GetTempPath());
        // 下载目录
        AddExisting(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) is { Length: > 0 } up
            ? Path.Combine(up, "Downloads")
            : null);
        // 用户常用程序目录（AppData Roaming/Local 顶层可执行驻留）
        AddExisting(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)));
        AddExisting(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"));
        // 常见恶意程序驻留位置
        AddExisting(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch"));
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (!string.IsNullOrEmpty(programData)) roots.Add(programData);

        return roots.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public List<string> BuildFullRange(IEnumerable<string>? drives = null)
    {
        if (drives != null && drives.Any())
            return drives.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        return DriveInfo.GetDrives()
            .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
            .Select(d => d.Name)
            .ToList();
    }

    public async Task<long> EstimateFileCountAsync(IEnumerable<string> roots, CancellationToken ct)
    {
        long count = 0;
        foreach (var root in roots)
        {
            if (!Directory.Exists(root)) continue;
            await Task.Run(() =>
            {
                try
                {
                    var q = new Queue<string>();
                    q.Enqueue(root);
                    while (q.Count > 0 && !ct.IsCancellationRequested && count < 5_000_000)
                    {
                        var dir = q.Dequeue();
                        IEnumerable<string>? entries = null;
                        try { entries = Directory.EnumerateFileSystemEntries(dir); }
                        catch (UnauthorizedAccessException) { }
                        catch (DirectoryNotFoundException) { }
                        catch (IOException) { }
                        if (entries == null) continue;
                        foreach (var e in entries)
                        {
                            try
                            {
                                var attr = File.GetAttributes(e);
                                if (attr.HasFlag(FileAttributes.ReparsePoint)) continue;
                                if (attr.HasFlag(FileAttributes.Directory)) q.Enqueue(e);
                                else count++;
                            }
                            catch (FileNotFoundException) { }
                            catch (DirectoryNotFoundException) { }
                            catch (UnauthorizedAccessException) { }
                            catch (IOException) { }
                        }
                    }
                }
                catch (Exception)
                {
                    // 估算失败不影响主流程
                }
            }, ct);
        }
        return count;
    }
}
