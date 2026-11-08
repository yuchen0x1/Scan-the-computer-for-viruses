using Microsoft.Win32;
using System.Security.Cryptography;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Platform.WinRegistry;
using PcSecurityCenter.Platform.Security;

namespace PcSecurityCenter.Platform.Software;

/// <summary>已安装软件枚举（卸载注册表，只读）。</summary>
public class WindowsInstalledAppsProvider : IInstalledAppsProvider
{
    public Task<List<InstalledAppInfo>> EnumerateAsync(CancellationToken ct = default) => Task.Run(() =>
    {
        var list = new List<InstalledAppInfo>();
        (RegistryKey hive, string sub, bool wow)[] roots =
        [
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", false),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", true),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", false),
        ];
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (hive, sub, wow) in roots)
        {
            RegistryKey? root = null;
            try { root = hive.OpenSubKey(sub); }
            catch (Exception) { continue; }
            if (root == null) continue;
            using (root)
            {
                foreach (var keyName in root.GetSubKeyNames())
                {
                    try
                    {
                        using var key = root.OpenSubKey(keyName);
                        if (key == null) continue;
                        var name = key.GetValue("DisplayName") as string;
                        if (string.IsNullOrWhiteSpace(name)) continue;
                        var fingerprint = name + "|" + key.GetValue("DisplayVersion");
                        if (!seen.Add(fingerprint)) continue;

                        var app = new InstalledAppInfo
                        {
                            DisplayName = name,
                            Version = key.GetValue("DisplayVersion") as string ?? "",
                            Publisher = key.GetValue("Publisher") as string ?? "",
                            InstallLocation = key.GetValue("InstallLocation") as string ?? "",
                            UninstallString = key.GetValue("UninstallString") as string ?? "",
                            InstallDate = key.GetValue("InstallDate") as string ?? "",
                            RegistryKey = $@"{(hive == Registry.LocalMachine ? "HKLM" : "HKCU")}\{sub}\{keyName}",
                        };
                        var size = key.GetValue("EstimatedSize");
                        if (size is int s) app.EstimatedSizeKb = (ulong)s;
                        if (app.Publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)) app.IsMicrosoft = true;

                        // 签名检查（仅对可定位的主程序，控制开销）
                        var exe = ResolveMainExe(app);
                        if (exe != null)
                        {
                            var v = SignatureVerifier.Verify(exe);
                            app.IsSigned = v.IsValid;
                            if (!v.IsValid && !app.IsMicrosoft)
                            {
                                var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                                if (exe.StartsWith(local, StringComparison.OrdinalIgnoreCase))
                                {
                                    app.RiskLevel = ThreatSeverity.Low;
                                    app.RiskNote = "主程序无有效签名且位于用户目录";
                                }
                            }
                            if (!string.IsNullOrEmpty(app.Publisher)) app.Publisher = app.Publisher;
                        }
                        list.Add(app);
                    }
                    catch (Exception) { }
                }
            }
        }
        return list.OrderBy(x => x.DisplayName).ToList();
    }, ct);

    private static string? ResolveMainExe(InstalledAppInfo app)
    {
        try
        {
            if (!string.IsNullOrEmpty(app.UninstallString))
            {
                var raw = app.UninstallString.Trim();
                if (raw.StartsWith('"')) raw = raw.Split('"')[1];
                else raw = raw.Split(' ')[0];
                if (File.Exists(raw) && raw.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return raw;
            }
            if (!string.IsNullOrEmpty(app.InstallLocation) && Directory.Exists(app.InstallLocation))
            {
                return Directory.EnumerateFiles(app.InstallLocation, "*.exe")
                    .OrderByDescending(f => new FileInfo(f).Length)
                    .FirstOrDefault();
            }
        }
        catch (Exception) { }
        return null;
    }

    public Task<List<ScheduledTaskInfo>> GetScheduledTasksAsync(CancellationToken ct = default)
        => new WindowsTasksAndServices().GetScheduledTasksAsync(ct);

    public Task<List<ServiceInfo>> GetServicesAsync(CancellationToken ct = default)
        => new WindowsTasksAndServices().GetServicesAsync(ct);
}

/// <summary>软件卸载入口（启动官方卸载字符串，需要用户确认；不静默卸载）。</summary>
public static class AppUninstaller
{
    /// <summary>通过资源管理器打开卸载入口（ms-settings 或官方卸载字符串）。返回 false 表示无法启动。</summary>
    public static bool LaunchUninstall(InstalledAppInfo app)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(app.UninstallString)) return false;
            var raw = app.UninstallString.Trim();
            // 禁止任何注入：UninstallString 来自注册表，仍按外壳正常解析执行
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c " + raw,   // 官方注册表卸载字符串可能带参数，需经 shell 解析
                UseShellExecute = true,
                CreateNoWindow = false,
            };
            // 更安全路径：如果是单纯的 msiexec/ms-settings，直接启动
            if (raw.StartsWith("ms-settings:", StringComparison.OrdinalIgnoreCase))
            {
                psi.FileName = raw;
                psi.Arguments = "";
                psi.UseShellExecute = true;
            }
            else if (raw.StartsWith("msiexec", StringComparison.OrdinalIgnoreCase))
            {
                psi.FileName = "msiexec.exe";
                var rest = raw["msiexec".Length..].Trim();
                psi.Arguments = rest;
                psi.UseShellExecute = true;
            }
            else if (raw.StartsWith('"'))
            {
                psi.FileName = raw.Split('"')[1];
                psi.Arguments = "";
                psi.UseShellExecute = true;
            }
            else
            {
                var space = raw.IndexOf(' ');
                var exe = space > 0 ? raw[..space] : raw;
                var args = space > 0 ? raw[(space + 1)..] : "";
                if (!File.Exists(exe)) return false;
                psi.FileName = exe;
                psi.Arguments = args;
                psi.UseShellExecute = true;
            }
            System.Diagnostics.Process.Start(psi);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
