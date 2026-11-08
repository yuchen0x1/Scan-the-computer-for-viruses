using System.Runtime.InteropServices;

namespace PcSecurityCenter.Platform.Security;

/// <summary>
/// 数字签名验证：调用 WinVerifyTrust（CryptoAPI 官方接口，与资源管理器"数字签名"页签一致）。
/// </summary>
public static class SignatureVerifier
{
    private static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;          // WTD_UI_NONE = 2
        public uint fdwRevocationChecks; // WTD_REVOKE_NONE = 0
        public uint dwUnionChoice;       // WTD_CHOICE_FILE = 1
        public IntPtr pFile;             // union
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern uint WinVerifyTrust(IntPtr hWnd, ref Guid actionId, ref WINTRUST_DATA data);

    /// <summary>验证结果。</summary>
    public sealed record VerifyResult(bool IsSigned, bool IsValid, string StatusText, string? Subject);

    /// <summary>验证文件签名（同步、快速、无 UI 弹窗）。发布者信息由 PowerShell 辅助读取。</summary>
    public static VerifyResult Verify(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            return new VerifyResult(false, false, "文件不存在", null);

        var infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            var info = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = Marshal.StringToHGlobalUni(filePath),
            };
            Marshal.StructureToPtr(info, infoPtr, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = 2, // WTD_UI_NONE：不弹任何 UI
                fdwRevocationChecks = 0,
                dwUnionChoice = 1, // WTD_CHOICE_FILE
                pFile = infoPtr,
            };

            var g = WintrustActionGenericVerifyV2;
            var hr = WinVerifyTrust(IntPtr.Zero, ref g, ref data);
            if (info.pcwszFilePath != IntPtr.Zero) { Marshal.FreeHGlobal(info.pcwszFilePath); info.pcwszFilePath = IntPtr.Zero; }

            return hr switch
            {
                0 => new VerifyResult(true, true, "签名有效", null),
                0x800B0100 => new VerifyResult(false, false, "未签名", null),
                0x800B0109 => new VerifyResult(true, false, "根证书不受信任", null),
                0x800B010A => new VerifyResult(true, false, "证书吊销列表不可用", null),
                0x800B010C => new VerifyResult(true, false, "签名无效", null),
                0x800B010E => new VerifyResult(true, false, "签名无效（策略不满足）", null),
                _ => new VerifyResult(hr != 0x800B0100, false, $"验证返回 0x{hr:X8}", null),
            };
        }
        catch (Exception ex)
        {
            return new VerifyResult(false, false, "验证异常：" + ex.Message, null);
        }
        finally
        {
            Marshal.FreeHGlobal(infoPtr);
        }
    }

    /// <summary>通过 PowerShell Get-AuthenticodeSignature 获取签名详情（发布者/状态，带缓存防抖）。</summary>
    private static readonly Dictionary<string, (bool? signed, string? subject, string? status)> ProbeCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object ProbeLock = new();

    public static (bool? signed, string? subject, string? status) ProbeViaPowerShell(string filePath)
    {
        lock (ProbeCache)
        {
            if (ProbeCache.TryGetValue(filePath, out var cached)) return cached;
        }
        var result = ProbeUncached(filePath);
        lock (ProbeCache)
        {
            ProbeCache[filePath] = result;
            if (ProbeCache.Count > 512) ProbeCache.Clear(); // 简单上限控制
        }
        return result;
    }

    private static (bool? signed, string? subject, string? status) ProbeUncached(string filePath)
    {
        try
        {
            const string script = """
$s = Get-AuthenticodeSignature -LiteralPath $env:PSC_FILE -ErrorAction Stop
@{ status = [int]$s.Status; subject = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' } } | ConvertTo-Json -Compress
""";
            var r = PowerShellRunner.RunAsync(script, new Dictionary<string, string> { ["file"] = filePath }, 30_000)
                .GetAwaiter().GetResult();
            var j = r.Json;
            if (j.ValueKind != JsonValueKind.Object) return (null, null, null);
            var status = j.TryGetProperty("status", out var sv) ? sv.GetInt32() : -1;
            var subject = j.TryGetProperty("subject", out var sj) && sj.ValueKind == JsonValueKind.String ? sj.GetString() : null;
            return (status == 0, subject, status switch
            {
                0 => "签名有效",
                1 => "签名存在但未验证",
                2 => "无签名",
                3 => "哈希不匹配（文件被修改）",
                4 => "签名者证书未受信任",
                5 => "签名者证书已过期",
                _ => $"状态 {status}",
            });
        }
        catch (Exception) { return (null, null, null); }
    }
}
