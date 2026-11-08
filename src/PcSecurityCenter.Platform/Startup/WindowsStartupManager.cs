using Microsoft.Win32;
using System.Diagnostics;
using System.ServiceProcess;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Platform.PowerShell;
using PcSecurityCenter.Platform.WinRegistry;
using PcSecurityCenter.Platform.Security;

namespace PcSecurityCenter.Platform.Startup;

/// <summary>
/// 启动项枚举与管理。禁用注册表启动项采用"值改名"方式（Run→_PSC_Disabled_Run），
/// 完整保留原值便于恢复；计划任务/服务的启停走官方 cmdlet 并需要提权确认。
/// </summary>
public class WindowsStartupManager : IStartupManager
{
    public Task<List<StartupItem>> EnumerateAsync(CancellationToken ct = default) => Task.Run(() =>
    {
        var list = new List<StartupItem>();
        EnumerateRunKeys(list);
        EnumerateStartupFolders(list);
        list.Sort((a, b) => string.Compare(a.Source, b.Source, StringComparison.Ordinal));
        return list;
    }, ct);

    private static void EnumerateRunKeys(List<StartupItem> list)
    {
        (RegistryKey hive, string sub, string source)[] keys =
        [
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"),
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce"),
            (Registry.LocalMachine, @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Wow6432Node\\...\\Run"),
        ];

        foreach (var (hive, sub, source) in keys)
        {
            foreach (var name in RegistryHelper.GetValueNames(hive, sub))
            {
                if (string.IsNullOrEmpty(name)) continue;
                // 跳过已被本工具禁用的项（另有"已禁用"分组展示）
                if (name.StartsWith(DisabledPrefix, StringComparison.Ordinal))
                {
                    var origName = name[DisabledPrefix.Length..];
                    var cmd = RegistryHelper.GetStringValue(hive, sub, name) ?? "";
                    list.Add(new StartupItem
                    {
                        Name = origName, Command = cmd, Location = sub, Source = source, Kind = "注册表",
                        Enabled = false,
                    });
                    continue;
                }
                var command = RegistryHelper.GetStringValue(hive, sub, name);
                if (string.IsNullOrEmpty(command)) continue;
                var item = new StartupItem
                {
                    Name = name, Command = command, Location = sub, Source = source, Kind = "注册表",
                };
                Analyze(item);
                list.Add(item);
            }
        }
    }

    public const string DisabledPrefix = "_PSC_Disabled_";

    private static void EnumerateStartupFolders(List<StartupItem> list)
    {
        foreach (var dir in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        })
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
            foreach (var f in Directory.EnumerateFiles(dir))
            {
                var item = new StartupItem
                {
                    Name = Path.GetFileNameWithoutExtension(f),
                    Command = f,
                    Location = dir,
                    Source = dir.Contains("ProgramData", StringComparison.OrdinalIgnoreCase) ? "公共启动文件夹" : "用户启动文件夹",
                    Kind = "启动文件夹",
                };
                Analyze(item);
                list.Add(item);
            }
        }
    }

    /// <summary>风险分析（保守规则）：无签名且位于临时目录 → 高风险；无签名 → 提示。</summary>
    internal static void Analyze(StartupItem item)
    {
        var exePath = ExtractExePath(item.Command);
        if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath)) return;
        try
        {
            var vi = FileVersionInfo.GetVersionInfo(exePath);
            item.Publisher = vi.CompanyName ?? "";
            if (item.Publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)) item.IsMicrosoft = true;
        }
        catch (Exception) { }
        var v = SignatureVerifier.Verify(exePath);
        item.IsSigned = v.IsValid;
        if (string.IsNullOrEmpty(item.Publisher)) item.Publisher = v.Subject ?? "";

        var temp = Path.GetTempPath();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!v.IsValid && (exePath.StartsWith(temp, StringComparison.OrdinalIgnoreCase)))
        {
            item.RiskLevel = ThreatSeverity.High;
            item.RiskNote = "无有效签名且位于临时目录";
        }
        else if (!v.IsValid && (exePath.StartsWith(localAppData, StringComparison.OrdinalIgnoreCase) || exePath.StartsWith(appData, StringComparison.OrdinalIgnoreCase)))
        {
            item.RiskLevel = ThreatSeverity.Medium;
            item.RiskNote = "无有效签名且位于用户可写目录";
        }
        else if (!v.IsValid && !item.IsMicrosoft)
        {
            item.RiskLevel = ThreatSeverity.Low;
            item.RiskNote = "未检测到有效数字签名";
        }
    }

    private static string? ExtractExePath(string command)
    {
        command = command.Trim();
        if (command.StartsWith('"'))
        {
            var end = command.IndexOf('"', 1);
            if (end > 1) return command[1..end];
        }
        var space = command.IndexOf(' ');
        var candidate = space > 0 ? command[..space] : command;
        if (File.Exists(candidate)) return candidate;
        if (command.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(command)) return command;
        return null;
    }

    public async Task<bool> SetEnabledAsync(StartupItem item, bool enabled)
    {
        try
        {
            if (item.Kind == "注册表")
            {
                var hive = item.Source.StartsWith("HKCU", StringComparison.Ordinal) ? Registry.CurrentUser : Registry.LocalMachine;
                var sub = item.Location;
                if (enabled)
                {
                    // 从禁用名恢复
                    var ok = RegistryHelper.RenameValue(hive, sub, DisabledPrefix + item.Name, item.Name);
                    return ok;
                }
                else
                {
                    var ok = RegistryHelper.RenameValue(hive, sub, item.Name, DisabledPrefix + item.Name);
                    return ok;
                }
            }
            if (item.Kind == "启动文件夹")
            {
                if (enabled) return false; // 文件被移走后无法一键恢复，UI 层应提示
                var file = item.Command;
                if (File.Exists(file))
                {
                    Directory.CreateDirectory(DisabledStartupDir);
                    var dest = Path.Combine(DisabledStartupDir, Path.GetFileName(file) + ".disabled");
                    File.Move(file, dest, overwrite: true);
                    return true;
                }
                return false;
            }
            return false;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static string DisabledStartupDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "PcSecurityCenter", "DisabledStartupItems");
}

/// <summary>计划任务/服务枚举（独立类，供高级工具页使用）。</summary>
public class WindowsTasksAndServices
{
    public async Task<List<ScheduledTaskInfo>> GetScheduledTasksAsync(CancellationToken ct = default)
    {
        const string script = """
$out = @()
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' } | ForEach-Object {
  $action = ''
  try { $action = ($_.Actions | ForEach-Object { ($_.Execute + ' ' + $_.Arguments).Trim() }) -join '; ' } catch { }
  $author = ''
  try { $author = $_.Author } catch { }
  $out += @{ path = $_.TaskPath; name = $_.TaskName; state = $_.State.ToString(); action = $action; author = $author }
}
$out | ConvertTo-Json -Compress -Depth 3
""";
        var r = await PowerShellRunner.RunAsync(script, timeoutMs: 120_000, ct: ct);
        var list = new List<ScheduledTaskInfo>();
        try
        {
            using var doc = JsonDocument.Parse(r.StdOut.Trim());
            var arr = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement
                : throw new JsonException("expected array");
            foreach (var t in arr.EnumerateArray())
            {
                var item = new ScheduledTaskInfo
                {
                    Path = t.GetProperty("path").GetString() ?? "",
                    Name = t.GetProperty("name").GetString() ?? "",
                    State = t.GetProperty("state").GetString() ?? "",
                    Action = t.GetProperty("action").GetString() ?? "",
                    Author = t.TryGetProperty("author", out var a) ? a.GetString() ?? "" : "",
                };
                AnalyzeTask(item);
                list.Add(item);
            }
        }
        catch (Exception) { }
        return list.OrderBy(x => x.Path).ToList();
    }

    /// <summary>计划任务风险规则：动作指向临时目录/用户目录且无签名 → 风险提示。</summary>
    internal static void AnalyzeTask(ScheduledTaskInfo t)
    {
        t.Enabled = t.State is "Ready" or "Running";
        var exe = t.Action.Split(' ')[0].Trim('"');
        if (string.IsNullOrEmpty(exe) || !File.Exists(exe)) return;
        var temp = Path.GetTempPath();
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (exe.StartsWith(temp, StringComparison.OrdinalIgnoreCase))
        {
            t.RiskLevel = ThreatSeverity.High;
            t.RiskNote = "计划任务执行临时目录中的程序";
        }
        else if (exe.StartsWith(local, StringComparison.OrdinalIgnoreCase) || exe.StartsWith(roaming, StringComparison.OrdinalIgnoreCase))
        {
            var sig = SignatureVerifier.Verify(exe);
            if (!sig.IsValid)
            {
                t.RiskLevel = ThreatSeverity.Medium;
                t.RiskNote = "计划任务执行用户目录中的未签名程序";
            }
        }
    }

    public async Task<List<ServiceInfo>> GetServicesAsync(CancellationToken ct = default)
    {
        return await Task.Run(() =>
        {
            var list = new List<ServiceInfo>();
            try
            {
                foreach (var svc in ServiceController.GetServices())
                {
                    var info = new ServiceInfo
                    {
                        Name = svc.ServiceName,
                        DisplayName = svc.DisplayName,
                        Status = svc.Status.ToString(),
                    };
                    try
                    {
                        var path = RegistryHelper.GetStringValue(Registry.LocalMachine,
                            $@"SYSTEM\CurrentControlSet\Services\{svc.ServiceName}", "ImagePath");
                        info.ExePath = path?.Replace("\"", "") ?? "";
                        if (info.ExePath.StartsWith("\\??\\", StringComparison.Ordinal)) info.ExePath = info.ExePath[4..];
                        info.StartMode = RegistryHelper.GetStringValue(Registry.LocalMachine,
                            $@"SYSTEM\CurrentControlSet\Services\{svc.ServiceName}", "Start") switch
                        {
                            "2" => "自动",
                            "3" => "手动",
                            "4" => "禁用",
                            var s => s ?? "",
                        };
                    }
                    catch (Exception) { }
                    list.Add(info);
                }
            }
            catch (Exception) { }
            return list.OrderBy(x => x.Name).ToList();
        }, ct);
    }
}
