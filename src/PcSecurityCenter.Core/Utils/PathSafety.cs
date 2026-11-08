namespace PcSecurityCenter.Core.Utils;

/// <summary>
/// 路径安全工具：集中处理路径规范化、越界防护与系统关键目录识别。
/// 所有删除/隔离/写入操作都必须经过这里的校验。
/// </summary>
public static class PathSafety
{
    /// <summary>规范化路径并在 basePath 约束下校验，防止路径遍历。失败返回 null。</summary>
    public static string? NormalizeInside(string basePath, string relative)
    {
        try
        {
            var baseFull = Path.GetFullPath(basePath);
            var full = Path.GetFullPath(Path.Combine(baseFull, relative));
            var cmp = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (!full.StartsWith(baseFull.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, cmp)
                && !string.Equals(full, baseFull.TrimEnd(Path.DirectorySeparatorChar), cmp))
                return null;
            return full;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>绝对路径规范化；非法或不存在时返回 null。</summary>
    public static string? NormalizeAbsolute(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path)) return null;
            if (path.IndexOf('\0') >= 0) return null;
            var full = Path.GetFullPath(path);
            return full;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static readonly string[] WindowsCriticalRoots =
    [
        @"C:\Windows",
        @"C:\Program Files",
        @"C:\Program Files (x86)",
        @"C:\ProgramData\Microsoft\Windows\Containers",
    ];

    /// <summary>是否为系统关键目录（含其子目录；这些目录默认禁止批量删除/隔离内容）。</summary>
    public static bool IsCriticalSystemPath(string path)
    {
        var full = NormalizeAbsolute(path);
        if (full == null) return true; // 无法解析的一律按关键路径处理（保守）
        foreach (var root in WindowsCriticalRoots)
        {
            if (full.Equals(root, StringComparison.OrdinalIgnoreCase)) return true;
            if (full.StartsWith(root.TrimEnd('\\') + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>路径是否位于 Windows 目录内（清理项需要在说明中标注）。</summary>
    public static bool IsUnderWindowsDir(string path)
    {
        var full = NormalizeAbsolute(path);
        return full != null && full.StartsWith(@"C:\Windows", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>确认目标可以删除：必须存在、不是目录树关键根、不是当前进程文件。</summary>
    public static bool IsSafeToDelete(string path)
    {
        var full = NormalizeAbsolute(path);
        if (full == null) return false;
        if (!File.Exists(full)) return false;
        try
        {
            var current = Environment.ProcessPath;
            if (current != null && string.Equals(full, current, StringComparison.OrdinalIgnoreCase)) return false;
        }
        catch (Exception) { }
        return true;
    }
}

/// <summary>字节大小格式化。</summary>
public static class SizeFormat
{
    public static string Format(long bytes)
    {
        const double KB = 1024, MB = KB * 1024, GB = MB * 1024, TB = GB * 1024;
        return Math.Abs(bytes) switch
        {
            < (long)KB => $"{bytes} B",
            < (long)MB => $"{bytes / KB:F1} KB",
            < (long)GB => $"{bytes / MB:F1} MB",
            < (long)TB => $"{bytes / GB:F2} GB",
            _ => $"{bytes / TB:F2} TB",
        };
    }
}
