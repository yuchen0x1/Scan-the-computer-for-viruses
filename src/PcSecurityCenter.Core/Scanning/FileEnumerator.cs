namespace PcSecurityCenter.Core.Scanning;

/// <summary>
/// 安全的文件枚举器：跳过重解析点（符号链接/挂载点）避免循环，
/// 容忍访问拒绝，支持取消。供扫描编排与磁盘分析复用。
/// </summary>
public static class FileEnumerator
{
    /// <summary>枚举 root 下所有普通文件（不跟随重解析点）。root 自身若是文件则返回它。</summary>
    public static IEnumerable<string> EnumerateFiles(string root, CancellationToken ct)
    {
        var attr = SafeAttributes(root);
        if (attr == null || attr.Value.HasFlag(FileAttributes.ReparsePoint)) yield break;
        if (!attr.Value.HasFlag(FileAttributes.Directory))
        {
            yield return root;
            yield break;
        }

        var queue = new Queue<string>();
        queue.Enqueue(root);
        while (queue.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var dir = queue.Dequeue();
            string[] entries;
            try { entries = Directory.GetFileSystemEntries(dir); }
            catch (UnauthorizedAccessException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            catch (IOException) { continue; }

            foreach (var e in entries)
            {
                ct.ThrowIfCancellationRequested();
                var a = SafeAttributes(e);
                if (a == null) continue;
                if (a.Value.HasFlag(FileAttributes.ReparsePoint)) continue; // 不跟随符号链接
                if (a.Value.HasFlag(FileAttributes.Directory)) queue.Enqueue(e);
                else yield return e;
            }
        }
    }

    /// <summary>枚举 root 下一级子目录（含自身）。</summary>
    public static IEnumerable<string> EnumerateDirectoriesShallow(string root)
    {
        yield return root;
        string[] dirs;
        try { dirs = Directory.GetDirectories(root); }
        catch (Exception) { yield break; }
        foreach (var d in dirs)
        {
            var a = SafeAttributes(d);
            if (a != null && !a.Value.HasFlag(FileAttributes.ReparsePoint)) yield return d;
        }
    }

    /// <summary>
    /// 把 root 切分为"互不包含、并集覆盖 root"的扫描单元（反链分区）。
    ///
    /// 为什么必须是反链：Defender 对每个投递目录执行**递归**扫描。若同时投递祖先与后代目录，
    /// 后代子树会被扫描多次（实测 21 文件的树可放大 3.29 倍），导致耗时成倍增加、
    /// FilesScanned 计数虚高、进度百分比失真。
    ///
    /// 规则：root 的直接子目录和 root 中的普通文件各为一个单元；root 无子目录与文件时作为一个单元。
    /// 同级目录互不包含，直接文件也不包含目录 → 满足反链；所有单元并集覆盖 root 的全部内容；
    /// 进度粒度保持在每盘十几个到几十个单元（另加少量根目录文件）。
    /// </summary>
    public static IEnumerable<string> PartitionForScan(string root)
    {
        var attr = SafeAttributes(root);
        if (attr == null || attr.Value.HasFlag(FileAttributes.ReparsePoint)) yield break;
        if (!attr.Value.HasFlag(FileAttributes.Directory))
        {
            yield return root;
            yield break;
        }

        var children = ChildDirectories(root).ToList();
        if (children.Count == 0)
        {
            yield return root;
            yield break;
        }

        foreach (var child in children) yield return child;
        foreach (var file in ChildFiles(root)) yield return file;
    }

    /// <summary>root 的直接普通文件（跳过重解析点，容忍访问拒绝）。root 本身不包含在内。</summary>
    private static IEnumerable<string> ChildFiles(string root)
    {
        string[] files;
        try { files = Directory.GetFiles(root); }
        catch (UnauthorizedAccessException) { yield break; }
        catch (DirectoryNotFoundException) { yield break; }
        catch (IOException) { yield break; }
        catch (ArgumentException) { yield break; }

        foreach (var file in files)
        {
            var a = SafeAttributes(file);
            if (a != null && !a.Value.HasFlag(FileAttributes.ReparsePoint)) yield return file;
        }
    }

    /// <summary>root 的直接子目录（跳过重解析点，容忍访问拒绝）。root 本身不包含在内。</summary>
    public static IEnumerable<string> ChildDirectories(string root)
    {
        string[] dirs;
        try { dirs = Directory.GetDirectories(root); }
        catch (UnauthorizedAccessException) { yield break; }
        catch (DirectoryNotFoundException) { yield break; }
        catch (IOException) { yield break; }
        catch (ArgumentException) { yield break; }

        foreach (var d in dirs)
        {
            var a = SafeAttributes(d);
            if (a != null && !a.Value.HasFlag(FileAttributes.ReparsePoint)) yield return d;
        }
    }

    /// <summary>candidate 是否为 ancestor 的后代或同一路径（"包含"关系）。</summary>
    public static bool IsSameOrDescendant(string candidate, string ancestor)
    {
        var c = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        var a = Path.TrimEndingDirectorySeparator(Path.GetFullPath(ancestor));
        if (string.Equals(c, a, StringComparison.OrdinalIgnoreCase)) return true;
        var prefix = Path.EndsInDirectorySeparator(a) ? a : a + Path.DirectorySeparatorChar;
        return c.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>移除重复或被祖先覆盖的根路径，避免跨根重复扫描；不遍历文件树。</summary>
    public static List<string> NormalizeRoots(IEnumerable<string> paths)
    {
        var roots = paths.Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(p => p.Length).ToList();
        var result = new List<string>();
        foreach (var root in roots)
            if (!result.Any(parent => IsSameOrDescendant(root, parent))) result.Add(root);
        return result;
    }

    /// <summary>验证一组路径构成反链（两两之间不存在包含关系，且无重复）。</summary>
    public static bool IsAntichain(IEnumerable<string> paths)
    {
        var list = paths.ToList();
        for (var i = 0; i < list.Count; i++)
        for (var j = 0; j < list.Count; j++)
        {
            if (i == j) continue;
            if (IsSameOrDescendant(list[i], list[j])) return false;
        }
        return true;
    }

    public static FileAttributes? SafeAttributes(string path)
    {
        try { return File.GetAttributes(path); }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
        catch (IOException) { return null; }
        catch (ArgumentException) { return null; }
    }
}
