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
        if (attr == null) yield break;
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
