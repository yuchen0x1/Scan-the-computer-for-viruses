using System.Security.Principal;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Platform.PowerShell;

namespace PcSecurityCenter.Platform.Security;

/// <summary>
/// 权限服务：默认最小权限运行；提权操作走白名单脚本模板（参数经环境变量传入，杜绝注入）。
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
        ElevatedOperation op, IReadOnlyDictionary<string, string>? args = null)
    {
        var (script, timeout) = BuildScript(op);
        if (script == null) return (false, $"未知操作 {op}");

        // 通过 -EncodedCommand + Start-Process -Verb RunAs 触发 UAC；
        // 参数以环境变量方式传给子进程（在 -EncodedCommand 内读取），全程无字符串拼接用户输入。
        var encoded = PowerShellRunner.Encode(script);

        var launcher = $"""
$op = '{op}'
$encoded = '{encoded}'
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'powershell.exe'
$psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encoded
$psi.Verb = 'RunAs'
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
$psi.EnvironmentVariables['PSC_OPARGS'] = '{op}'
""";
        // 逐个注入参数环境变量（键/值均为受控字典内容，值经单引号 PS 字面量转义）
        if (args != null)
        {
            foreach (var (k, v) in args)
            {
                var safeK = new string(k.Where(char.IsLetterOrDigit).ToArray());
                if (safeK.Length == 0) return (false, "非法参数名");
                var safeV = v.Replace("'", "''");
                launcher += $"\n$psi.EnvironmentVariables['PSC_{safeK.ToUpperInvariant()}'] = '{safeV}'";
            }
        }
        launcher += """
$out = $psi.EnvironmentVariables['PSC_OPARGS']
try {
  $p = [System.Diagnostics.Process]::Start($psi)
  $outTask = $p.StandardOutput.ReadToEndAsync()
  $errTask = $p.StandardError.ReadToEndAsync()
  $p.WaitForExit(600000) | Out-Null
  $text = $outTask.Result
  if ($errTask.Result) { $text = $text + [Environment]::NewLine + $errTask.Result }
  if (-not $text) { $text = '（无输出）' }
  @{ ok = ($p.ExitCode -eq 0); out = $text } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; out = $_.Exception.Message } | ConvertTo-Json -Compress
}
""";

        var r = await PowerShellRunner.RunAsync(launcher, timeoutMs: 660_000).ConfigureAwait(false);
        var j = r.Json;
        if (j.ValueKind != JsonValueKind.Object)
            return (false, "提权执行未返回结果（可能用户取消了 UAC 确认）");
        var ok = j.TryGetProperty("ok", out var okv) && okv.ValueKind == JsonValueKind.True;
        var output = j.TryGetProperty("out", out var ov) ? ov.GetString() ?? "" : "";
        return (ok, output);
    }

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
  'RESTOREPOINT_OK'
} catch { 'RESTOREPOINT_FAIL: ' + $_.Exception.Message }
finally {
  if ($null -ne $oldFreq) {
    try { Set-ItemProperty $freqKey -Name SystemRestorePointCreationFrequency -Value $oldFreq } catch { }
  }
}
""", 600_000),
        ElevatedOperation.RunSfcVerifyOnly => (
            """
$out = & "$env:WINDIR\System32\sfc.exe" /verifyonly 2>&1
$out | Out-String
if ($LASTEXITCODE -eq 0) { exit 0 } else { exit $LASTEXITCODE }
""", 600_000),
        ElevatedOperation.RunDismScanHealth => (
            """
$out = & "$env:WINDIR\System32\Dism.exe" /Online /Cleanup-Image /ScanHealth 2>&1
$out | Out-String
exit $LASTEXITCODE
""", 600_000),
        ElevatedOperation.RunChkdskReadOnly => (
            """
$drive = $env:PSC_DRIVE
if ($drive -notmatch '^[A-Za-z]:$') { 'ILLEGAL_DRIVE'; exit 2 }
$out = & chkdsk $drive 2>&1
$out | Out-String
exit $LASTEXITCODE
""", 600_000),
        ElevatedOperation.DisableScheduledTask or ElevatedOperation.EnableScheduledTask => (
            """
$path = $env:PSC_TASKPATH
$name = $env:PSC_TASKNAME
$enable = $env:PSC_ENABLE -eq '1'
if ($enable) { Enable-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction Stop | Out-Null }
else { Disable-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction Stop | Out-Null }
'TASK_OK'
""", 120_000),
        ElevatedOperation.DisableService or ElevatedOperation.EnableService => (
            """
$name = $env:PSC_SVCNAME
$enable = $env:PSC_ENABLE -eq '1'
$svc = Get-Service -Name $name -ErrorAction Stop
Set-Service -Name $name -StartupType $(if ($enable) { 'Automatic' } else { 'Disabled' }) -ErrorAction Stop
'SVC_OK'
""", 120_000),
        _ => (null, 0),
    };
}
