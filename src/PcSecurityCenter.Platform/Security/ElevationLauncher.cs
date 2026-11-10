using System.ComponentModel;
using System.Diagnostics;

namespace PcSecurityCenter.Platform.Security;

/// <summary>
/// 提权子进程的启动配置与结果判定（独立出来便于单元测试锁定行为）。
///
/// 关键约束（都是 .NET/Windows 的硬限制，不能"优化"掉）：
/// 1. <c>UseShellExecute</c> 必须为 true，否则 <c>Verb = "RunAs"</c> 被静默忽略，
///    进程以普通权限启动——历史上这里正是因此导致"提权"从未生效。
/// 2. <c>UseShellExecute = true</c> 时禁止 <c>RedirectStandardOutput/Error</c>，
///    也禁止访问 <c>EnvironmentVariables</c>（会抛 InvalidOperationException），
///    所以参数与结果都必须走 -EncodedCommand 与结果文件。
/// </summary>
public static class ElevationLauncher
{
    /// <summary>用户取消 UAC 时 Process.Start 抛出的 Win32 错误码。</summary>
    public const int ErrorCancelled = 1223;

    /// <summary>构造已触发 UAC 的 powershell 启动信息。</summary>
    public static ProcessStartInfo CreateStartInfo(string encodedCommand)
    {
        if (string.IsNullOrWhiteSpace(encodedCommand))
            throw new ArgumentException("编码命令不能为空", nameof(encodedCommand));

        return new ProcessStartInfo
        {
            FileName = PowerShellExe,
            Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand " + encodedCommand,
            UseShellExecute = true,
            Verb = "RunAs",
            WindowStyle = ProcessWindowStyle.Hidden,
            CreateNoWindow = true,
        };
    }

    /// <summary>是否为"用户拒绝 UAC 授权"。</summary>
    public static bool IsUserCancelled(Win32Exception ex) => ex.NativeErrorCode == ErrorCancelled;

    /// <summary>PowerShell 5.1 绝对路径；找不到时回退到 PATH 查找。</summary>
    public static string PowerShellExe
    {
        get
        {
            var candidate = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell", "v1.0", "powershell.exe");
            return File.Exists(candidate) ? candidate : "powershell.exe";
        }
    }
}
