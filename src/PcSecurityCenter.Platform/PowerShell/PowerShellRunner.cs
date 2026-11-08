using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace PcSecurityCenter.Platform.PowerShell;

/// <summary>
/// out-of-proc Windows PowerShell 5.1 执行器。
/// 安全设计：
/// 1. 脚本以 Base64(-EncodedCommand UTF-16LE) 传递 —— 数据永远不进入命令行拼接；
/// 2. 参数通过环境变量传入脚本（PS 侧读取 $env:PSC_PARAM），彻底杜绝命令注入；
/// 3. 输出统一为 JSON（stdout 单行 JSON 对象），stderr 仅记录日志；
/// 4. 全部调用点为内置白名单脚本，无任何用户输入参与脚本逻辑。
/// </summary>
public static class PowerShellRunner
{
    private static readonly string PsExe = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");

    static PowerShellRunner()
    {
        if (!File.Exists(PsExe)) PsExe = "powershell.exe";
    }

    public sealed class PsResult
    {
        public bool Success { get; init; }
        public int ExitCode { get; init; }
        public string StdOut { get; init; } = string.Empty;
        public string StdErr { get; init; } = string.Empty;
        public string Error { get; init; } = string.Empty;
        public JsonElement Json => ParseJson(StdOut);
        public JsonElement JsonFromTag(string tag)
        {
            // stdout 约定：以 [TAG] 起始的单行 JSON
            foreach (var line in StdOut.Split('\n'))
            {
                var t = line.Trim();
                if (t.StartsWith($"[{tag}]", StringComparison.Ordinal))
                    return ParseJson(t[$"[{tag}]".Length..]);
            }
            return default;
        }
        private static JsonElement ParseJson(string text)
        {
            try
            {
                var t = text.Trim();
                if (t.StartsWith('[') || t.StartsWith('{'))
                    return JsonSerializer.Deserialize<JsonElement>(t);
            }
            catch (JsonException) { }
            return default;
        }
    }

    /// <summary>执行内置脚本。params 中的值以环境变量形式传入（键名自动加 PSC_ 前缀）。</summary>
    public static async Task<PsResult> RunAsync(
        string script,
        IReadOnlyDictionary<string, string>? vars = null,
        int timeoutMs = 120_000,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(script)) throw new ArgumentException("脚本不能为空");
        var psi = new ProcessStartInfo
        {
            FileName = PsExe,
            Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + Encode(script),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = Environment.SystemDirectory,
        };
        if (vars != null)
        {
            foreach (var (k, v) in vars)
                psi.EnvironmentVariables[$"PSC_{k.ToUpperInvariant()}"] = v ?? string.Empty;
        }

        using var proc = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        proc.OutputDataReceived += (_, e) => { if (e.Data != null) stdout.AppendLine(e.Data); };
        proc.ErrorDataReceived += (_, e) => { if (e.Data != null) stderr.AppendLine(e.Data); };

        try
        {
            proc.Start();
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(timeoutMs);
            await proc.WaitForExitAsync(timeoutCts.Token);
            return new PsResult
            {
                Success = proc.ExitCode == 0,
                ExitCode = proc.ExitCode,
                StdOut = stdout.ToString(),
                StdErr = stderr.ToString(),
            };
        }
        catch (OperationCanceledException)
        {
            TryKill(proc);
            throw;
        }
        catch (Exception ex)
        {
            TryKill(proc);
            return new PsResult { Success = false, Error = ex.Message };
        }
    }

    private static void TryKill(Process proc)
    {
        try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); }
        catch (Exception) { }
    }

    public static string Encode(string script) =>
        Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

    /// <summary>读取环境变量的脚本片段（防注入参数读取约定）。</summary>
    public static string ReadVar(string name) => $"$env:PSC_{name.ToUpperInvariant()}";
}
