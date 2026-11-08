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
        public uint fdwRevocationChecks; // WTD_REVOKE_NONE = 0 / WTD_REVOKE_WHOLECHAIN = 1
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

    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    // 只用本地缓存的 CRL/OCSP 做吊销检查，避免联网拉取导致长时间卡顿
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    /// <summary>验证结果。</summary>
    public sealed record VerifyResult(bool IsSigned, bool IsValid, string StatusText, string? Subject);

    /// <summary>验证文件签名（同步、快速、无 UI 弹窗）。发布者信息由 PowerShell 辅助读取。
    /// checkRevocation 为 true 时启用整链吊销检查（仅用本地缓存，不联网拉取）。</summary>
    public static VerifyResult Verify(string filePath, bool checkRevocation = false)
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
                fdwRevocationChecks = checkRevocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE,
                dwUnionChoice = 1, // WTD_CHOICE_FILE
                pFile = infoPtr,
                dwProvFlags = checkRevocation ? WTD_CACHE_ONLY_URL_RETRIEVAL : 0,
            };

            var g = WintrustActionGenericVerifyV2;
            var hr = WinVerifyTrust(IntPtr.Zero, ref g, ref data);
            if (info.pcwszFilePath != IntPtr.Zero) { Marshal.FreeHGlobal(info.pcwszFilePath); info.pcwszFilePath = IntPtr.Zero; }

            return hr switch
            {
                0 => new VerifyResult(true, true, "签名有效", null),
                0x800B0100 => new VerifyResult(false, false, "未签名", null),
                0x800B0109 => new VerifyResult(true, false, "根证书不受信任", null),
                0x800B010A => new VerifyResult(true, false, "证书链不完整（中间证书缺失）", null),
                0x800B010C or 0x80092010 => new VerifyResult(true, false, "证书已吊销", null),
                0x800B010E => new VerifyResult(true, false, "签名无效（策略不满足）", null),
                // 吊销状态无法核实（本地无 CRL/OCSP 缓存）：签名本身有效，如实标注未核实
                0x80092012 => new VerifyResult(true, true, "签名有效（吊销状态未能核实）", null),
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

    public static async Task<(bool? signed, string? subject, string? status)> ProbeAsync(string filePath)
    {
        lock (ProbeCache)
        {
            if (ProbeCache.TryGetValue(filePath, out var cached)) return cached;
        }
        var result = await ProbeUncachedAsync(filePath).ConfigureAwait(false);
        lock (ProbeCache)
        {
            ProbeCache[filePath] = result;
            if (ProbeCache.Count > 512) ProbeCache.Clear(); // 简单上限控制
        }
        return result;
    }

    private static async Task<(bool? signed, string? subject, string? status)> ProbeUncachedAsync(string filePath)
    {
        try
        {
            const string script = """
$s = Get-AuthenticodeSignature -LiteralPath $env:PSC_FILE -ErrorAction Stop
@{ status = [int]$s.Status; subject = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' } } | ConvertTo-Json -Compress
""";
            var r = await PowerShellRunner.RunAsync(script, new Dictionary<string, string> { ["file"] = filePath }, 30_000)
                .ConfigureAwait(false);
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
