using System.Text.Json;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Platform.PowerShell;
using PcSecurityCenter.Platform.WinRegistry;

namespace PcSecurityCenter.Platform.SecurityChecks;

/// <summary>
/// 系统安全检查服务：所有结论来自真实接口读取；
/// 无法读取的项目明确标记为 NoPermission / NotSupported / Error，绝不默认显示安全。
/// </summary>
public class SystemSecurityCheckService : ISecurityCheckService
{
    private readonly IDefenderClient _defender;
    private readonly IScoreCalculator _score;
    private readonly IPermissionService _permission;

    public SystemSecurityCheckService(IDefenderClient defender, IScoreCalculator score, IPermissionService permission)
    {
        _defender = defender;
        _score = score;
        _permission = permission;
    }

    public async Task<List<SecurityCheckItem>> RunAllChecksAsync(CancellationToken ct = default)
    {
        var checks = new List<SecurityCheckItem>();

        // ---- 1. Defender（并行）----
        var defenderTask = CheckDefenderAsync(ct);
        // ---- 2. 一揽子快速检查（单次 PS 进程）----
        var fastTask = RunFastChecksAsync(ct);
        // ---- 3. Windows Update（慢，独立）----
        var updateTask = CheckWindowsUpdateAsync(ct);

        checks.AddRange(await defenderTask.ConfigureAwait(false));
        checks.AddRange(await fastTask.ConfigureAwait(false));
        checks.AddRange(await updateTask.ConfigureAwait(false));
        return checks;
    }

    public SecurityScore CalculateScore(IReadOnlyList<SecurityCheckItem> checks) => _score.FromChecks(checks);

    // ============ Defender ============
    private async Task<List<SecurityCheckItem>> CheckDefenderAsync(CancellationToken ct)
    {
        var list = new List<SecurityCheckItem>();
        var st = await _defender.GetStatusAsync(ct).ConfigureAwait(false);

        list.Add(new SecurityCheckItem
        {
            Id = "defender-engine",
            Name = "Microsoft Defender 防病毒引擎",
            Category = CheckCategories.Protection,
            Weight = 15,
            Status = st.Installed && st.AntivirusEnabled && st.EngineAvailable ? CheckStatus.Ok : CheckStatus.Risk,
            Result = st.Installed
                ? $"引擎 {(st.EngineAvailable ? "正常" : "异常")}；实时防护 {(st.RealTimeProtection ? "已开启" : "已关闭")}"
                : "未检测到 Microsoft Defender（可能被第三方杀软替代或系统不支持）",
            Method = "PowerShell: Get-MpComputerStatus",
            RiskExplanation = st.Installed && !st.AntivirusEnabled ? "Defender 防病毒功能被禁用，系统失去基线病毒防护。" : "",
            Recommendation = st.Installed ? (st.AntivirusEnabled && st.EngineAvailable ? "保持现状。" : "请通过 Windows 安全中心重新启用 Defender 实时防护。") : "本工具将仅使用智能风险规则引擎，检测能力受限。",
        });

        list.Add(new SecurityCheckItem
        {
            Id = "defender-signature",
            Name = "病毒库更新状态",
            Category = CheckCategories.Protection,
            Weight = 10,
            Status = st.SignatureLastUpdated switch
            {
                null => st.Installed ? CheckStatus.Error : CheckStatus.NotSupported,
                var d when (DateTime.Now - d.Value).TotalDays <= 7 => CheckStatus.Ok,
                var d when (DateTime.Now - d.Value).TotalDays <= 14 => CheckStatus.Warning,
                _ => CheckStatus.Risk,
            },
            Result = st.SignatureLastUpdated != null
                ? $"病毒库版本 {st.SignatureVersion}，更新于 {st.SignatureLastUpdated:yyyy-MM-dd HH:mm}"
                : "无法读取病毒库时间",
            Method = "PowerShell: Get-MpComputerStatus",
            RiskExplanation = "病毒库过期会导致新型威胁无法检出。",
            Recommendation = st.SignatureLastUpdated != null && (DateTime.Now - st.SignatureLastUpdated.Value).TotalDays > 7 ? "建议立即更新病毒库（可在病毒查杀页执行）。" : "保持现状。",
        });

        list.Add(new SecurityCheckItem
        {
            Id = "defender-quickscan",
            Name = "最近快速扫描",
            Category = CheckCategories.Protection,
            Weight = 6,
            Status = st.LastQuickScan switch
            {
                null => st.Installed ? CheckStatus.Warning : CheckStatus.NotSupported,
                var d when (DateTime.Now - d.Value).TotalDays <= 7 => CheckStatus.Ok,
                _ => CheckStatus.Warning,
            },
            Result = st.LastQuickScan != null ? $"上次快速扫描：{st.LastQuickScan:yyyy-MM-dd HH:mm}" : "从未执行过快速扫描",
            Method = "PowerShell: Get-MpComputerStatus",
            Recommendation = st.LastQuickScan == null || (DateTime.Now - st.LastQuickScan.Value).TotalDays > 7 ? "建议每 1-2 周至少执行一次快速扫描。" : "保持现状。",
        });

        // 活动威胁（近 30 天记录）
        try
        {
            var threats = await _defender.GetThreatDetectionsAsync(ct).ConfigureAwait(false);
            var active = threats.Count;
            list.Add(new SecurityCheckItem
            {
                Id = "active-threats",
                Name = "Defender 威胁检测记录（近 30 天）",
                Category = CheckCategories.Protection,
                Weight = 10,
                Status = active == 0 ? CheckStatus.Ok : CheckStatus.Risk,
                Result = active == 0 ? "无威胁记录" : $"存在 {active} 条威胁检测记录",
                Method = "PowerShell: Get-MpThreatDetection + Get-MpThreat",
                RiskExplanation = active > 0 ? "存在未被处理的威胁记录，可能仍有残留风险。" : "",
                Recommendation = active > 0 ? "请到「病毒查杀」页查看并处理威胁（优先隔离）。" : "保持现状。",
            });
        }
        catch (Exception ex)
        {
            list.Add(new SecurityCheckItem
            {
                Id = "active-threats", Name = "Defender 威胁检测记录", Category = CheckCategories.Protection, Weight = 10,
                Status = CheckStatus.Error, Result = "读取失败：" + ex.Message,
                Method = "PowerShell: Get-MpThreatDetection", Recommendation = "可稍后重试或查看日志。",
            });
        }
        return list;
    }

    // ============ 快速一揽子检查 ============
    private async Task<List<SecurityCheckItem>> RunFastChecksAsync(CancellationToken ct)
    {
        const string script = """
$out = New-Object System.Collections.Generic.List[string]
function Tag($t, $obj) { $out.Add("[$t]" + ($obj | ConvertTo-Json -Compress -Depth 4)) }

# 防火墙
try {
  $fw = Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { @{ p = $_.Name; en = [bool]$_.Enabled; in = $_.DefaultInboundAction; out = $_.DefaultOutboundAction } }
  Tag 'fw' @{ ok = $true; profiles = $fw }
} catch { Tag 'fw' @{ ok = $false; err = $_.Exception.Message } }

# UAC
try {
  $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  $lua = (Get-ItemProperty -Path $k -Name EnableLUA -ErrorAction Stop).EnableLUA
  $consent = (Get-ItemProperty -Path $k -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
  Tag 'uac' @{ lua = [int]$lua; consent = $consent }
} catch { Tag 'uac' @{ err = $_.Exception.Message } }

# SecureBoot（非 UEFI/权限不足时分别标记）
try {
  $sb = Confirm-SecureBootUEFI -ErrorAction Stop
  Tag 'sb' @{ on = [bool]$sb }
} catch {
  $m = $_.Exception.Message
  $kind = 'error'
  if ($m -match 'UEFI|BIOS|firmware|不受支持|not supported') { $kind = 'unsupported' }
  elseif ($m -match '拒绝访问|denied|admin|管理员') { $kind = 'noperm' }
  Tag 'sb' @{ kind = $kind; err = $m }
}

# TPM
try {
  $tpm = Get-Tpm -ErrorAction Stop
  Tag 'tpm' @{ present = [bool]$tpm.TpmPresent; ready = [bool]$tpm.TpmReady; enabled = [bool]$tpm.TpmEnabled }
} catch {
  $m = $_.Exception.Message
  $kind = if ($m -match '拒绝访问|denied|admin|管理员') { 'noperm' } elseif ($m -match '没有 TPM|no TPM|not found|找不到') { 'absent' } else { 'error' }
  Tag 'tpm' @{ kind = $kind; err = $m }
}

# BitLocker（系统盘）
try {
  $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  Tag 'bl' @{ prot = [int]$bl.ProtectionStatus; pct = [int]$bl.EncryptionPercentage; state = $bl.VolumeStatus }
} catch {
  $m = $_.Exception.Message
  $kind = if ($m -match '拒绝访问|denied|admin|管理员') { 'noperm' } else { 'error' }
  Tag 'bl' @{ kind = $kind; err = $m }
}

# Windows 安全中心注册的防病毒产品
try {
  $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { $_.displayName }
  Tag 'wsc' @{ ok = $true; products = $av }
} catch { Tag 'wsc' @{ ok = $false; err = $_.Exception.Message } }

# 本地账户与管理员
try {
  $users = Get-LocalUser -ErrorAction Stop | ForEach-Object { @{ n = $_.Name; en = [bool]$_.Enabled; nopass = [bool]$_.PasswordRequired -eq $false -and $_.Enabled } }
  $admins = @()
  try { $admins = @(Get-LocalGroupMember -Group Administrators -ErrorAction Stop | ForEach-Object { $_.PrincipalSource.ToString() + ':' + $_.Name }) } catch { }
  Tag 'acct' @{ users = $users; admins = $admins; adminErr = '' }
} catch { Tag 'acct' @{ err = $_.Exception.Message } }

# 远程桌面
try {
  $ts = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
  $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
  Tag 'rdp' @{ deny = [int]$ts; nla = $nla }
} catch { Tag 'rdp' @{ err = $_.Exception.Message } }

# 最新补丁时间
try {
  $last = (Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
  Tag 'hotfix' @{ last = if ($last) { $last.ToString('yyyy-MM-dd') } else { '' } }
} catch { Tag 'hotfix' @{ err = $_.Exception.Message } }

# SMBv1
try {
  $smb = Get-SmbServerConfiguration -ErrorAction Stop
  Tag 'smb1' @{ v1 = [bool]$smb.EnableSMB1Protocol }
} catch {
  $m = $_.Exception.Message
  $kind = if ($m -match '拒绝访问|denied|admin|管理员') { 'noperm' } else { 'error' }
  Tag 'smb1' @{ kind = $kind; err = $m }
}

$out
""";
        var r = await PowerShellRunner.RunAsync(script, timeoutMs: 120_000, ct: ct).ConfigureAwait(false);
        var checks = new List<SecurityCheckItem>();

        foreach (var line in r.StdOut.Split('\n'))
        {
            var t = line.Trim();
            if (!t.StartsWith('[')) continue;
            var end = t.IndexOf(']');
            if (end < 0) continue;
            var tag = t[1..end];
            JsonElement json;
            try { json = JsonSerializer.Deserialize<JsonElement>(t[(end + 1)..]); }
            catch (JsonException) { continue; }

            switch (tag)
            {
                case "fw": AddFirewallChecks(checks, json); break;
                case "uac": AddUacCheck(checks, json); break;
                case "sb": AddSecureBootCheck(checks, json); break;
                case "tpm": AddTpmCheck(checks, json); break;
                case "bl": AddBitlockerCheck(checks, json); break;
                case "wsc": AddWscCheck(checks, json); break;
                case "acct": AddAccountCheck(checks, json); break;
                case "rdp": AddRdpCheck(checks, json); break;
                case "hotfix": AddHotfixCheck(checks, json); break;
                case "smb1": AddSmb1Check(checks, json); break;
            }
        }
        if (checks.Count == 0)
        {
            checks.Add(new SecurityCheckItem
            {
                Id = "fast-batch", Name = "系统快速检查", Category = CheckCategories.Policy, Weight = 0,
                Status = CheckStatus.Error, Result = "检查脚本执行失败：" + (r.Error ?? r.StdErr ?? "无输出"),
                Method = "PowerShell 批量检查", Recommendation = "请查看应用日志。",
            });
        }
        return checks;
    }

    private static bool B(JsonElement o, string n) => o.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.True;
    private static int I(JsonElement o, string n) => o.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : -1;
    private static string S(JsonElement o, string n) => o.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static void AddFirewallChecks(List<SecurityCheckItem> list, JsonElement json)
    {
        if (!B(json, "ok"))
        {
            list.Add(new SecurityCheckItem { Id = "firewall", Name = "Windows 防火墙", Category = CheckCategories.Network, Weight = 10, Status = CheckStatus.Error, Result = "读取失败：" + S(json, "err"), Method = "PowerShell: Get-NetFirewallProfile", Recommendation = "请查看日志。" });
            return;
        }
        var profiles = json.GetProperty("profiles");
        foreach (var p in profiles.EnumerateArray())
        {
            var name = S(p, "p");
            var enabled = B(p, "en");
            var inbound = S(p, "in");
            list.Add(new SecurityCheckItem
            {
                Id = "firewall-" + name.ToLowerInvariant(),
                Name = $"防火墙配置文件（{name}）",
                Category = CheckCategories.Network,
                Weight = 4,
                Status = enabled ? (inbound == "Allow" ? CheckStatus.Warning : CheckStatus.Ok) : CheckStatus.Risk,
                Result = $"{(enabled ? "已启用" : "已禁用")}；默认入站 {inbound}；默认出站 {S(p, "out")}",
                Method = "PowerShell: Get-NetFirewallProfile",
                RiskExplanation = !enabled ? "防火墙配置文件被禁用，入站流量不受系统防火墙保护。" : (inbound == "Allow" ? "默认入站策略为允许，建议恢复为阻止。" : ""),
                Recommendation = !enabled ? "请到 Windows 安全中心启用防火墙。" : (inbound == "Allow" ? "建议将默认入站策略改回「阻止」。本工具不直接修改防火墙。" : "保持现状。"),
            });
        }
    }

    private static void AddUacCheck(List<SecurityCheckItem> list, JsonElement json)
    {
        if (json.TryGetProperty("err", out _))
        {
            list.Add(new SecurityCheckItem { Id = "uac", Name = "用户账户控制 (UAC)", Category = CheckCategories.Policy, Weight = 8, Status = CheckStatus.Error, Result = "读取失败", Method = "注册表只读: Policies\\System", Recommendation = "请查看日志。" });
            return;
        }
        var lua = I(json, "lua");
        var consent = I(json, "consent");
        var status = lua == 1 ? (consent is 0 ? CheckStatus.Warning : CheckStatus.Ok) : CheckStatus.Risk;
        list.Add(new SecurityCheckItem
        {
            Id = "uac",
            Name = "用户账户控制 (UAC)",
            Category = CheckCategories.Policy,
            Weight = 8,
            Status = status,
            Result = $"EnableLUA={lua}；管理员批准提示级别={consent}",
            Method = "注册表只读: HKLM\\...\\Policies\\System",
            RiskExplanation = lua != 1 ? "UAC 已关闭，恶意程序更容易静默获取管理员权限。" : (consent == 0 ? "管理员权限提升无需确认，存在误授权风险。" : ""),
            Recommendation = lua != 1 ? "强烈建议在控制面板中重新开启 UAC。" : (consent == 0 ? "建议将 UAC 提示级别恢复为默认（仅在应用变暗时提示）。" : "保持现状。"),
        });
    }

    private static void AddSecureBootCheck(List<SecurityCheckItem> list, JsonElement json)
    {
        string kind = S(json, "kind");
        SecurityCheckItem item;
        if (json.TryGetProperty("on", out var on))
        {
            item = new SecurityCheckItem
            {
                Id = "secureboot", Name = "Secure Boot 安全启动", Category = CheckCategories.Encryption, Weight = 5,
                Status = on.ValueKind == JsonValueKind.True ? CheckStatus.Ok : CheckStatus.Warning,
                Result = on.ValueKind == JsonValueKind.True ? "已启用" : "未启用",
                Method = "PowerShell: Confirm-SecureBootUEFI",
                RiskExplanation = on.ValueKind == JsonValueKind.True ? "" : "安全启动关闭时， bootkit 类恶意软件更容易植入。",
                Recommendation = on.ValueKind == JsonValueKind.True ? "保持现状。" : "如为 UEFI 固件，建议在 BIOS 中开启 Secure Boot。",
            };
        }
        else
        {
            item = new SecurityCheckItem
            {
                Id = "secureboot", Name = "Secure Boot 安全启动", Category = CheckCategories.Encryption, Weight = 5,
                Status = kind == "unsupported" ? CheckStatus.NotSupported : kind == "noperm" ? CheckStatus.NoPermission : CheckStatus.Error,
                Result = kind == "unsupported" ? "当前固件不支持 UEFI Secure Boot 查询（可能为传统 BIOS 或虚拟机）" : kind == "noperm" ? "权限不足：该检查需要管理员权限" : "检查失败：无法读取 Secure Boot 状态；本结果不代表已启用或存在风险。",
                Method = "PowerShell: Confirm-SecureBootUEFI",
                Recommendation = kind == "noperm" ? "以管理员身份运行本工具后重试。" : "如设备为传统 BIOS 则无法检查。",
            };
        }
        list.Add(item);
    }

    private static void AddTpmCheck(List<SecurityCheckItem> list, JsonElement json)
    {
        string kind = S(json, "kind");
        var status = json.TryGetProperty("present", out _) ? (B(json, "present") ? CheckStatus.Ok : CheckStatus.Warning) :
            kind == "noperm" ? CheckStatus.NoPermission : kind == "absent" ? CheckStatus.NotSupported : CheckStatus.Error;
        var result = json.TryGetProperty("present", out _)
            ? $"TPM 存在={B(json, "present")}；已就绪={B(json, "ready")}；已启用={B(json, "enabled")}"
            : kind == "noperm" ? "权限不足：TPM 查询需要管理员权限" : kind == "absent" ? "本机未检测到 TPM" : "检查失败：" + S(json, "err");
        list.Add(new SecurityCheckItem
        {
            Id = "tpm", Name = "TPM 可信平台模块", Category = CheckCategories.Encryption, Weight = 5, Status = status,
            Result = result, Method = "PowerShell: Get-Tpm",
            RiskExplanation = "TPM 用于 BitLocker 与凭据保护，缺失会降低基线安全。",
            Recommendation = status == CheckStatus.Warning ? "如主板支持，建议在 BIOS 中启用 TPM。" : "如需详细检查请以管理员身份运行。",
        });
    }

    private static void AddBitlockerCheck(List<SecurityCheckItem> list, JsonElement json)
    {
        string kind = S(json, "kind");
        var hasData = json.TryGetProperty("prot", out _);
        var prot = I(json, "prot");
        var status = hasData ? (prot == 1 ? CheckStatus.Ok : CheckStatus.Warning) : kind == "noperm" ? CheckStatus.NoPermission : CheckStatus.Error;
        list.Add(new SecurityCheckItem
        {
            Id = "bitlocker", Name = "BitLocker 系统盘加密", Category = CheckCategories.Encryption, Weight = 5, Status = status,
            Result = hasData ? $"保护状态={prot}（1=开启）；加密进度={I(json, "pct")}%；{S(json, "state")}"
                : kind == "noperm" ? "权限不足：BitLocker 查询需要管理员权限" : "检查失败：" + S(json, "err"),
            Method = "PowerShell: Get-BitLockerVolume -MountPoint 系统盘",
            RiskExplanation = "系统盘未加密时，物理接触设备可离线读取数据。",
            Recommendation = prot == 1 || (hasData == false && kind == "noperm") ? "如需检查请以管理员运行。" : "如设备支持，建议开启 BitLocker 设备加密。",
        });
    }

    private static void AddWscCheck(List<SecurityCheckItem> list, JsonElement json)
    {
        if (!B(json, "ok"))
        {
            list.Add(new SecurityCheckItem { Id = "wsc", Name = "Windows 安全中心注册状态", Category = CheckCategories.Protection, Weight = 5, Status = CheckStatus.NotSupported, Result = "无法读取安全中心（可能为服务器系统或被策略禁用）", Method = "WMI: root\\SecurityCenter2", Recommendation = "如为家庭版/专业版系统，此项通常可读取。" });
            return;
        }
        var products = new List<string>();
        if (json.TryGetProperty("products", out var arr) && arr.ValueKind == JsonValueKind.Array)
            foreach (var p in arr.EnumerateArray()) products.Add(p.GetString() ?? "");
        list.Add(new SecurityCheckItem
        {
            Id = "wsc", Name = "Windows 安全中心注册的防病毒产品", Category = CheckCategories.Protection, Weight = 5,
            Status = products.Count > 0 ? CheckStatus.Ok : CheckStatus.Risk,
            Result = products.Count > 0 ? string.Join("、", products.Where(x => !string.IsNullOrEmpty(x))) : "没有防病毒产品向安全中心注册",
            Method = "WMI 只读: root\\SecurityCenter2\\AntiVirusProduct",
            RiskExplanation = products.Count == 0 ? "安全中心未登记任何防病毒产品，实时防护可能缺失。" : "",
            Recommendation = products.Count == 0 ? "请确认杀毒软件安装状态。" : "保持现状。",
        });
    }

    private static void AddAccountCheck(List<SecurityCheckItem> list, JsonElement json)
    {
        if (json.TryGetProperty("err", out _))
        {
            list.Add(new SecurityCheckItem { Id = "accounts", Name = "本地账户安全", Category = CheckCategories.Account, Weight = 8, Status = CheckStatus.Error, Result = "读取失败：" + S(json, "err"), Method = "PowerShell: Get-LocalUser", Recommendation = "请查看日志。" });
            return;
        }
        var users = json.GetProperty("users");
        var enabled = 0; var noPass = 0; var guest = false;
        foreach (var u in users.EnumerateArray())
        {
            if (B(u, "en")) enabled++;
            if (B(u, "nopass")) noPass++;
            if (S(u, "n").Equals("Guest", StringComparison.OrdinalIgnoreCase) && B(u, "en")) guest = true;
        }
        var adminCount = json.TryGetProperty("admins", out var admins) && admins.ValueKind == JsonValueKind.Array ? admins.EnumerateArray().Count() : 0;

        var status = noPass > 0 ? CheckStatus.Risk : guest ? CheckStatus.Warning : adminCount > 3 ? CheckStatus.Warning : CheckStatus.Ok;
        list.Add(new SecurityCheckItem
        {
            Id = "accounts", Name = "本地账户安全", Category = CheckCategories.Account, Weight = 8, Status = status,
            Result = $"启用账户 {enabled} 个；管理员组成员 {adminCount} 个；无密码账户 {noPass} 个；Guest {(guest ? "已启用" : "未启用")}",
            Method = "PowerShell: Get-LocalUser + Get-LocalGroupMember",
            RiskExplanation = noPass > 0 ? "存在启用且无密码的账户，任何网络访问者都可能直接登录。" : guest ? "Guest 账户启用会增加攻击面。" : adminCount > 3 ? "管理员数量偏多，误操作与提权风险上升。" : "",
            Recommendation = noPass > 0 ? "立即为无密码账户设置强密码。" : guest ? "建议禁用 Guest 账户。" : "保持现状。",
        });
    }

    private static void AddRdpCheck(List<SecurityCheckItem> list, JsonElement json)
    {
        if (json.TryGetProperty("err", out _))
        {
            list.Add(new SecurityCheckItem { Id = "rdp", Name = "远程桌面配置", Category = CheckCategories.Account, Weight = 5, Status = CheckStatus.Error, Result = "读取失败", Method = "注册表只读: Terminal Server", Recommendation = "请查看日志。" });
            return;
        }
        var deny = I(json, "deny");
        var nla = I(json, "nla");
        var enabled = deny == 0;
        list.Add(new SecurityCheckItem
        {
            Id = "rdp", Name = "远程桌面 (RDP)", Category = CheckCategories.Account, Weight = 5,
            Status = !enabled ? CheckStatus.Ok : (nla == 1 ? CheckStatus.Warning : CheckStatus.Risk),
            Result = !enabled ? "远程桌面已关闭" : $"远程桌面已开启；NLA 网络级认证={(nla == 1 ? "已启用" : "未启用")}",
            Method = "注册表只读: HKLM\\...\\Terminal Server",
            RiskExplanation = enabled && nla != 1 ? "RDP 开放且未启用 NLA，暴露在网络上时极易被暴力破解。" : enabled ? "RDP 开放会增加攻击面，需确保强密码与防火墙限制。" : "",
            Recommendation = !enabled ? "保持现状。" : (nla == 1 ? "确保仅信任网络可访问，使用强密码。" : "建议启用 NLA，或关闭不使用的远程桌面。"),
        });
    }

    private static void AddHotfixCheck(List<SecurityCheckItem> list, JsonElement json)
    {
        var last = S(json, "last");
        var status = DateTime.TryParse(last, out var d)
            ? ((DateTime.Now - d).TotalDays <= 60 ? CheckStatus.Ok : CheckStatus.Warning)
            : CheckStatus.Warning;
        list.Add(new SecurityCheckItem
        {
            Id = "hotfix", Name = "系统补丁更新记录", Category = CheckCategories.Update, Weight = 7, Status = status,
            Result = string.IsNullOrEmpty(last) ? "未读取到补丁安装记录" : $"最近补丁安装时间：{last}",
            Method = "PowerShell: Get-HotFix",
            RiskExplanation = "长期未打补丁的系统存在已知漏洞被利用的风险。",
            Recommendation = status == CheckStatus.Warning ? "请到 Windows 更新中检查并安装最新补丁。" : "保持现状。",
        });
    }

    private static void AddSmb1Check(List<SecurityCheckItem> list, JsonElement json)
    {
        string kind = S(json, "kind");
        var hasData = json.TryGetProperty("v1", out _);
        var v1 = hasData && B(json, "v1");
        list.Add(new SecurityCheckItem
        {
            Id = "smbv1", Name = "SMBv1 协议", Category = CheckCategories.Network, Weight = 4,
            Status = hasData ? (v1 ? CheckStatus.Risk : CheckStatus.Ok) : kind == "noperm" ? CheckStatus.NoPermission : CheckStatus.Error,
            Result = hasData ? (v1 ? "SMBv1 已启用" : "SMBv1 已禁用") : kind == "noperm" ? "权限不足：需要管理员权限读取 SMB 配置" : "检查失败：" + S(json, "err"),
            Method = "PowerShell: Get-SmbServerConfiguration",
            RiskExplanation = "SMBv1 是 WannaCry 等勒索软件利用的老旧协议，应禁用。",
            Recommendation = v1 ? "建议在「启用或关闭 Windows 功能」中关闭 SMB 1.0。" : "保持现状。",
        });
    }

    // ============ Windows Update（COM，慢） ============
    private async Task<List<SecurityCheckItem>> CheckWindowsUpdateAsync(CancellationToken ct)
    {
        const string script = """
$ErrorActionPreference = 'Continue'
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  $result = $searcher.Search("IsInstalled=0 and IsHidden=0")
  $titles = @($result.Updates | Select-Object -First 6 | ForEach-Object { $_.Title })
  @{ ok = $true; count = $result.Updates.Count; titles = $titles } | ConvertTo-Json -Compress -Depth 3
} catch {
  @{ ok = $false; err = $_.Exception.Message } | ConvertTo-Json -Compress
}
""";
        var r = await PowerShellRunner.RunAsync(script, timeoutMs: 300_000, ct: ct).ConfigureAwait(false);
        var j = r.Json;
        if (j.ValueKind != JsonValueKind.Object || !B(j, "ok"))
        {
            var err = S(j, "err");
            return new List<SecurityCheckItem>
            {
                new() { Id = "wupending", Name = "待安装的 Windows 更新", Category = CheckCategories.Update, Weight = 10,
                    Status = err.Contains("拒绝访问") || err.Contains("denied", StringComparison.OrdinalIgnoreCase) ? CheckStatus.NoPermission : CheckStatus.Error,
                    Result = "无法通过 Windows Update COM 接口完成在线搜索：" + err,
                    Method = "COM: Microsoft.Update.Session.Search",
                    Recommendation = "可手动打开「设置 → Windows 更新」检查。", },
            };
        }
        var count = I(j, "count");
        var titles = new List<string>();
        if (j.TryGetProperty("titles", out var arr) && arr.ValueKind == JsonValueKind.Array)
            foreach (var t in arr.EnumerateArray()) titles.Add(t.GetString() ?? "");
        return new List<SecurityCheckItem>
        {
            new()
            {
                Id = "wupending", Name = "待安装的 Windows 更新", Category = CheckCategories.Update, Weight = 10,
                Status = count switch { 0 => CheckStatus.Ok, <= 5 => CheckStatus.Warning, _ => CheckStatus.Risk },
                Result = count == 0 ? "没有待安装的关键更新" : $"有 {count} 个待安装更新，如：{string.Join("；", titles)}",
                Method = "COM: Microsoft.Update.Session.Search（在线查询 Microsoft Update 服务器）",
                RiskExplanation = count > 5 ? "累积大量未安装更新，已知漏洞暴露窗口变长。" : "",
                Recommendation = count > 0 ? "请到「设置 → Windows 更新」安装待更新项。" : "保持现状。",
            },
        };
    }
}
