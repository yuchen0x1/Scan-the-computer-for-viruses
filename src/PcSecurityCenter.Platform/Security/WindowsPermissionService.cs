using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Platform.PowerShell;

namespace PcSecurityCenter.Platform.Security;

/// <summary>
/// 权限服务：默认最小权限运行；提权操作走白名单脚本模板。
///
/// 提权机制（重要）：
/// - .NET 中 <c>UseShellExecute=false</c> 会静默忽略 <c>Verb=RunAs</c>，导致"提权"实际以普通权限执行。
///   因此这里必须使用 <c>UseShellExecute=true</c>。
/// - 但 <c>UseShellExecute=true</c> 禁止重定向 stdout/stderr，也禁止设置环境变量，
///   所以操作参数与执行结果都通过"脚本内嵌 + 结果文件"传递：
///   父进程把操作脚本与参数一起编码为 -EncodedCommand，子进程把结果 JSON 写入临时文件，
///   父进程读取后删除。任何环节缺失都按失败处理，绝不把"没跑成"报成"成功"。
/// - 用户取消 UAC 时子进程启动抛 Win32Exception(1223)，单独识别并给出手势化提示。
/// </summary>
public class WindowsPermissionService : IPermissionService
{
    public bool IsElevated { get; } = CheckElevated();

    public string ElevationHint => IsElevated
        ? "当前以管理员身份运行，全部检查可用"
        : "当前为标准权限运行（推荐）；部分系统级检查（TPM/BitLocker/Secure Boot 等）会显示「权限不足」";

    private static bool CheckElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception) { return false; }
    }

    public async Task<(bool Success, string Output)> RunElevatedAsync(
        ElevatedOperation op, IReadOnlyDictionary<string, string>? args = null,
        CancellationToken ct = default)
    {
        var (script, timeout) = BuildScript(op);
        if (script == null) return (false, $"未知操作 {op}");

        // 参数名只允许字母数字，值按 PowerShell 单引号字面量转义后内嵌进脚本。
        // 由于走 -EncodedCommand（UTF-16LE base64），参数不进入命令行，天然不受引号/空格/管道影响。
        var header = new System.Text.StringBuilder();
        if (args != null)
        {
            foreach (var (k, v) in args)
            {
                var safeKey = new string(k.Where(char.IsLetterOrDigit).ToArray());
                if (safeKey.Length == 0) return (false, "非法参数名");
                header.Append("$env:PSC_").Append(safeKey.ToUpperInvariant())
                      .Append(" = '").Append(EscapePsSingleQuoted(v)).AppendLine("'");
            }
        }

        var resultPath = Path.Combine(Path.GetTempPath(), $"psc_elev_{Guid.NewGuid():N}.json");
        // 结果文件路径同样按单引号字面量转义，避免临时目录含特殊字符时脚本语法错误。
        var wrapper = header + $$"""
$__resultPath = '{{EscapePsSingleQuoted(resultPath)}}'
$__ok = $false
$__out = ''
try {
    $__isAdmin = ([Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $__isAdmin) {
        $__out = 'ELEVATION_NOT_APPLIED'
    } else {
{{script}}
    }
} catch {
    $__ok = $false
    $__out = $_.Exception.Message
}
$__payload = @{
    ok      = [bool]$__ok
    out     = [string]$__out
    elevated = [bool]$__isAdmin
} | ConvertTo-Json -Compress -Depth 3
try {
    [IO.File]::WriteAllText($__resultPath, $__payload, (New-Object System.Text.UTF8Encoding($false)))
} catch { }
if ($__ok) { exit 0 } else { exit 1 }
""";

        var encoded = PowerShellRunner.Encode(wrapper);
        var psi = ElevationLauncher.CreateStartInfo(encoded);

        try
        {
            using var proc = Process.Start(psi);
            if (proc == null)
                return (false, "提权进程未能启动（系统未返回进程对象）。");

            // WaitForExit(int) 不支持取消；用带取消的轮询，保证界面能响应"停止等待"。
            var deadline = DateTime.UtcNow.AddMilliseconds(timeout);
            while (!proc.WaitForExit(250))
            {
                if (ct.IsCancellationRequested)
                {
                    TryKill(proc);
                    return (false, "已取消等待提权操作完成（后台命令可能仍在运行）。");
                }
                if (DateTime.UtcNow >= deadline)
                {
                    TryKill(proc);
                    return (false, $"提权操作超时（{timeout / 1000} 秒）未返回结果。");
                }
            }
            proc.WaitForExit(); // 排空退出状态

            return ReadResult(resultPath, proc.ExitCode);
        }
        catch (Win32Exception ex) when (ElevationLauncher.IsUserCancelled(ex))
        {
            return (false, "已取消提权：用户拒绝了 UAC 管理员授权请求，操作未执行。");
        }
        catch (Win32Exception ex)
        {
            return (false, $"无法启动提权进程：{ex.Message}（错误码 {ex.NativeErrorCode}）");
        }
        catch (InvalidOperationException ex)
        {
            return (false, "提权进程启动配置无效：" + ex.Message);
        }
        finally
        {
            try { if (File.Exists(resultPath)) File.Delete(resultPath); } catch (Exception) { }
        }
    }

    /// <summary>读取子进程写回的结果文件；缺失或格式异常一律按失败处理。</summary>
    private static (bool Success, string Output) ReadResult(string resultPath, int exitCode)
    {
        if (!File.Exists(resultPath))
            return (false, $"提权进程已退出（代码 {exitCode}）但没有返回结果文件，操作结果未知，请以系统实际状态为准。");

        string text;
        try { text = File.ReadAllText(resultPath); }
        catch (Exception ex) { return (false, "读取提权结果失败：" + ex.Message); }

        try
        {
            using var doc = JsonDocument.Parse(text);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return (false, "提权结果格式异常，操作结果未知。");

            var ok = root.TryGetProperty("ok", out var okv) && okv.ValueKind == JsonValueKind.True;
            var output = root.TryGetProperty("out", out var ov) && ov.ValueKind == JsonValueKind.String
                ? ov.GetString() ?? string.Empty : string.Empty;
            var elevated = root.TryGetProperty("elevated", out var ev) && ev.ValueKind == JsonValueKind.True;

            if (!elevated)
                return (false, "提权未生效：子进程仍以标准权限运行，操作未获得管理员权限。请确认 UAC 设置后重试。");

            if (string.IsNullOrWhiteSpace(output))
                output = ok ? "操作已完成（无输出）。" : $"操作失败（退出代码 {exitCode}，无输出）。";
            return (ok, output);
        }
        catch (JsonException)
        {
            return (false, "提权结果不是合法 JSON，操作结果未知。");
        }
    }

    private static void TryKill(Process proc)
    {
        try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); }
        catch (Exception) { }
    }

    /// <summary>PowerShell 单引号字面量转义：' → ''。这是唯一需要的转义（无变量展开）。</summary>
    public static string EscapePsSingleQuoted(string value) => value.Replace("'", "''");

    /// <summary>
    /// 白名单脚本模板。约定：脚本必须给 <c>$__ok</c> 与 <c>$__out</c> 赋值，
    /// 且**不得调用 exit**（否则会跳过结果文件写入）。
    /// </summary>
    private static (string?, int) BuildScript(ElevatedOperation op) => op switch
    {
        ElevatedOperation.CreateRestorePoint => (
            """
    $desc = $env:PSC_DESC
    $freqKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
    $oldFreq = $null
    try {
        $range = Get-ItemProperty $freqKey -Name SystemRestorePointCreationFrequency -ErrorAction SilentlyContinue
        if ($range) { $oldFreq = $range.SystemRestorePointCreationFrequency }
        if ($range -and $range.SystemRestorePointCreationFrequency -gt 0) {
            Set-ItemProperty $freqKey -Name SystemRestorePointCreationFrequency -Value 0
        }
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description $desc -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        $__ok = $true
        $__out = '还原点已创建。'
    } finally {
        if ($null -ne $oldFreq) {
            try { Set-ItemProperty $freqKey -Name SystemRestorePointCreationFrequency -Value $oldFreq } catch { }
        }
    }
""", 600_000),
        ElevatedOperation.RunSfcVerifyOnly => (
            """
    $out = & "$env:WINDIR\System32\sfc.exe" /verifyonly 2>&1 | Out-String
    $code = $LASTEXITCODE
    $__ok = ($code -eq 0)
    $__out = $out
    if (-not $__ok) { $__out = $__out + [Environment]::NewLine + "sfc.exe 退出代码：$code" }
""", 600_000),
        ElevatedOperation.RunDismScanHealth => (
            """
    $out = & "$env:WINDIR\System32\Dism.exe" /Online /Cleanup-Image /ScanHealth 2>&1 | Out-String
    $code = $LASTEXITCODE
    $__ok = ($code -eq 0)
    $__out = $out
    if (-not $__ok) { $__out = $__out + [Environment]::NewLine + "Dism.exe 退出代码：$code" }
""", 600_000),
        ElevatedOperation.RunChkdskReadOnly => (
            """
    $drive = $env:PSC_DRIVE
    if ($drive -notmatch '^[A-Za-z]:$') {
        $__ok = $false
        $__out = '非法的驱动器参数（期望形如 C:）。'
    } else {
        $out = & chkdsk $drive 2>&1 | Out-String
        $code = $LASTEXITCODE
        $__ok = ($code -eq 0)
        $__out = $out
        if (-not $__ok) { $__out = $__out + [Environment]::NewLine + "chkdsk 退出代码：$code" }
    }
""", 600_000),
        ElevatedOperation.DisableScheduledTask or ElevatedOperation.EnableScheduledTask => (
            """
    $path = $env:PSC_TASKPATH
    $name = $env:PSC_TASKNAME
    $enable = $env:PSC_ENABLE -eq '1'
    if ([string]::IsNullOrWhiteSpace($name)) {
        $__ok = $false
        $__out = '缺少计划任务名称。'
    } else {
        if ($enable) { Enable-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction Stop | Out-Null }
        else { Disable-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction Stop | Out-Null }
        $__ok = $true
        $__out = $(if ($enable) { "已启用计划任务：$path$name" } else { "已禁用计划任务：$path$name" })
    }
""", 120_000),
        ElevatedOperation.DisableService or ElevatedOperation.EnableService => (
            """
    $name = $env:PSC_SVCNAME
    $enable = $env:PSC_ENABLE -eq '1'
    if ([string]::IsNullOrWhiteSpace($name)) {
        $__ok = $false
        $__out = '缺少服务名称。'
    } else {
        $svc = Get-Service -Name $name -ErrorAction Stop
        Set-Service -Name $name -StartupType $(if ($enable) { 'Automatic' } else { 'Disabled' }) -ErrorAction Stop
        $__ok = $true
        $__out = $(if ($enable) { "服务 $name 已设为自动启动。" } else { "服务 $name 已禁用。" })
    }
""", 120_000),
        _ => (null, 0),
    };
}
