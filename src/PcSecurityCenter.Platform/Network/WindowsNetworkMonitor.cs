using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Platform.PowerShell;
using PcSecurityCenter.Platform.Security;

namespace PcSecurityCenter.Platform.Network;

/// <summary>网络安全监控实现。可疑连接仅做风险提示（进程位置/签名分析），不做任何封禁。</summary>
public class WindowsNetworkMonitor : INetworkMonitor
{
    public async Task<List<NetworkAdapterInfo>> GetAdaptersAsync(CancellationToken ct = default)
    {
        return await Task.Run(() =>
        {
            var list = new List<NetworkAdapterInfo>();
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                var props = nic.GetIPProperties();
                var info = new NetworkAdapterInfo
                {
                    Name = nic.Name,
                    Description = nic.Description,
                    Status = nic.OperationalStatus.ToString(),
                    MacAddress = string.Join('-', nic.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2"))),
                };
                foreach (var ip in props.UnicastAddresses)
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork || ip.Address.AddressFamily == AddressFamily.InterNetworkV6)
                        info.IpAddresses.Add(ip.Address.ToString());
                info.Gateway = props.GatewayAddresses.FirstOrDefault()?.Address.ToString() ?? "";
                info.DnsServers = props.DnsAddresses.Select(a => a.ToString()).ToList();
                var st = nic.GetIPv4Statistics();
                info.BytesSent = (ulong)st.BytesSent;
                info.BytesReceived = (ulong)st.BytesReceived;
                info.IsVirtual = nic.Description.Contains("virtual", StringComparison.OrdinalIgnoreCase)
                              || nic.Description.Contains("VMware", StringComparison.OrdinalIgnoreCase)
                              || nic.Description.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase)
                              || nic.Description.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase)
                              || nic.Description.Contains("loopback", StringComparison.OrdinalIgnoreCase);
                list.Add(info);
            }
            return list;
        }, ct);
    }

    public Task<List<TcpConnectionInfo>> GetTcpConnectionsAsync(CancellationToken ct = default) =>
        Task.Run(() =>
        {
            var list = new List<TcpConnectionInfo>();
            // 带属主 PID 的 TCP 表（官方 API GetExtendedTcpTable）
            var rows = GetTcpTableWithPid();
            var procCache = new Dictionary<int, (string name, string path, bool? signed)>();
            foreach (var row in rows)
            {
                var c = new TcpConnectionInfo
                {
                    LocalAddress = row.local.ToString(),
                    LocalPort = row.localPort,
                    RemoteAddress = row.remote.ToString(),
                    RemotePort = row.remotePort,
                    State = row.state.ToString(),
                    ProcessId = row.pid,
                };
                if (row.pid > 0)
                {
                    if (!procCache.TryGetValue(row.pid, out var p))
                    {
                        try
                        {
                            var proc = System.Diagnostics.Process.GetProcessById(row.pid);
                            string path = "";
                            try { path = proc.MainModule?.FileName ?? ""; } catch (Exception) { }
                            var signed = string.IsNullOrEmpty(path) ? (bool?)null : SignatureVerifier.Verify(path).IsValid;
                            p = (proc.ProcessName, path, signed);
                        }
                        catch (Exception) { p = ("未知进程", "", null); }
                        procCache[row.pid] = p;
                    }
                    c.ProcessName = p.name;
                    c.ProcessPath = p.path;
                    c.IsSigned = p.signed == true;
                    AnalyzeSuspicious(c);
                }
                list.Add(c);
            }
            return list.OrderByDescending(x => x.State == "Established").ThenBy(x => x.ProcessName).ToList();
        }, ct);

    /// <summary>可疑连接规则（保守、可解释）：出站到公网 + 进程位于临时/下载目录，或进程无签名且位于用户可写目录。</summary>
    private static void AnalyzeSuspicious(TcpConnectionInfo c)
    {
        if (c.State != "Established" && c.State != "SynSent") return;
        if (string.IsNullOrEmpty(c.RemoteAddress) || string.IsNullOrEmpty(c.ProcessPath)) return;
        if (!IPAddress.TryParse(c.RemoteAddress, out var ip)) return;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168)
                || b[0] == 127 || b[0] == 169 && b[1] == 254) return; // 内网地址不算
            if (b[0] >= 224) return; // 组播/保留
        }
        else if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return;

        var pathLower = c.ProcessPath.ToLowerInvariant();
        var temp = Path.GetTempPath().ToLowerInvariant();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData).ToLowerInvariant();
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads").ToLowerInvariant();

        if (pathLower.StartsWith(temp) || pathLower.StartsWith(downloads))
        {
            c.IsSuspicious = true;
            c.SuspiciousReason = "进程位于临时/下载目录且正在连接公网";
        }
        else if (pathLower.StartsWith(localAppData) && !c.IsSigned)
        {
            c.IsSuspicious = true;
            c.SuspiciousReason = "进程位于用户目录且无有效数字签名，正在连接公网";
        }
    }

    public async Task<List<FirewallProfileInfo>> GetFirewallProfilesAsync(CancellationToken ct = default)
    {
        const string script = """
Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { @{ p = $_.Name; en = [bool]$_.Enabled; in = $_.DefaultInboundAction; out = $_.DefaultOutboundAction } } | ConvertTo-Json -Compress
""";
        var r = await PowerShellRunner.RunAsync(script, timeoutMs: 45_000, ct: ct);
        var list = new List<FirewallProfileInfo>();
        try
        {
            using var doc = JsonDocument.Parse(r.StdOut.Trim());
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
                foreach (var p in doc.RootElement.EnumerateArray())
                    list.Add(new FirewallProfileInfo
                    {
                        ProfileName = p.GetProperty("p").GetString() ?? "",
                        Enabled = p.GetProperty("en").GetBoolean(),
                        InboundAction = p.GetProperty("in").GetString() ?? "",
                        OutboundAction = p.GetProperty("out").GetString() ?? "",
                    });
        }
        catch (Exception) { }
        return list;
    }

    public Task<(string ProxyServer, string ProxyOverride, bool ProxyEnabled)> GetProxyAsync() =>
        Task.Run(() =>
        {
            var enable = RegistryHelper.ReadInt(Microsoft.Win32.Registry.CurrentUser,
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable") == 1;
            var server = RegistryHelper.ReadString(Microsoft.Win32.Registry.CurrentUser,
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer") ?? "";
            var over = RegistryHelper.ReadString(Microsoft.Win32.Registry.CurrentUser,
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyOverride") ?? "";
            return (server, over, enable);
        });

    public Task<HostsFileReport> InspectHostsFileAsync() => Task.Run(() =>
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");
        var report = new HostsFileReport { FilePath = path };
        try
        {
            var lines = File.ReadAllLines(path);
            report.RawContent = string.Join('\n', lines.Take(400));
            foreach (var raw in lines)
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;
                report.TotalEntries++;
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    var ip = parts[0];
                    var host = parts[1].ToLowerInvariant();
                    var isLocal = ip is "127.0.0.1" or "::1" or "0.0.0.0";
                    if (!isLocal)
                    {
                        report.ActiveRedirects++;
                        report.NonLocalRedirects.Add($"{host} → {ip}");
                    }
                    else if (host is not ("localhost") )
                    {
                        report.ActiveRedirects++;
                    }
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            report.FileLockedByOther = true;
        }
        catch (Exception)
        {
            report.FileLockedByOther = true;
        }
        return report;
    });

    public Task<List<string>> GetDnsServersAsync() => Task.Run(() =>
    {
        var set = new List<string>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                     .Where(n => n.OperationalStatus == OperationalStatus.Up))
            set.AddRange(nic.GetIPProperties().DnsAddresses.Select(a => a.ToString()));
        return set.Distinct().ToList();
    });

    public Task FlushDnsAsync() => Task.Run(() =>
    {
        // 固定命令，无用户输入参与
        using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
            "ipconfig", "/flushdns") { CreateNoWindow = true, UseShellExecute = false });
        p?.WaitForExit(15_000);
    });

    public Task<NetworkTrafficInfo> GetTotalTrafficSampleAsync() =>
        Task.FromResult(SampleTotalNetwork());

    private (DateTime time, ulong sent, ulong recv) _lastTotals;
    private NetworkTrafficInfo SampleTotalNetwork()
    {
        ulong sent = 0, recv = 0;
        var now = DateTime.UtcNow;
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                     .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
        {
            var st = nic.GetIPv4Statistics();
            sent += (ulong)st.BytesSent;
            recv += (ulong)st.BytesReceived;
        }
        var result = new NetworkTrafficInfo { AdapterName = "全部活动适配器" };
        if (_lastTotals.time != default)
        {
            var dt = (now - _lastTotals.time).TotalSeconds;
            if (dt > 0.2)
            {
                result.UploadBytesPerSec = Math.Max(0, (sent - _lastTotals.sent) / dt);
                result.DownloadBytesPerSec = Math.Max(0, (recv - _lastTotals.recv) / dt);
            }
        }
        _lastTotals = (now, sent, recv);
        return result;
    }

    // ---------------- GetExtendedTcpTable P/Invoke ----------------
    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

    private const int TcpTableOwnerPidAll = 5;
    private const int AfInet = 2;

    // Fields are populated by Marshal.PtrToStructure from the native MIB_TCPROW_OWNER_PID buffer.
    #pragma warning disable CS0649
    private struct MibTcpRowOwnerPid
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }
    #pragma warning restore CS0649

    private static readonly (IPAddress local, ushort localPort, IPAddress remote, ushort remotePort, string state, int pid)[] EmptyRows = Array.Empty<(IPAddress, ushort, IPAddress, ushort, string, int)>();

    private static IReadOnlyList<(IPAddress local, ushort localPort, IPAddress remote, ushort remotePort, string state, int pid)> GetTcpTableWithPid()
    {
        var results = new List<(IPAddress, ushort, IPAddress, ushort, string, int)>();
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AfInet, TcpTableOwnerPidAll, 0);
        if (size <= 0) return EmptyRows;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, true, AfInet, TcpTableOwnerPidAll, 0) != 0)
                return EmptyRows;
            var count = Marshal.ReadInt32(buffer, 0); // dwNumEntries
            nint basePtr = (nint)(buffer.ToInt64() + 4);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(basePtr + (nint)(i * rowSize));
                var local = new IPAddress(BitConverter.GetBytes(row.localAddr));
                var remote = new IPAddress(BitConverter.GetBytes(row.remoteAddr));
                results.Add((
                    local,
                    (ushort)IPAddress.NetworkToHostOrder((short)(row.localPort >> 8)),
                    remote,
                    (ushort)IPAddress.NetworkToHostOrder((short)(row.remotePort >> 8)),
                    ((TcpState)row.state).ToString(),
                    (int)row.owningPid));
            }
            return results;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
