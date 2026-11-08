using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;

namespace PcSecurityCenter.Platform.Performance;

/// <summary>
/// 真实硬件性能采集器：
/// - CPU：PerformanceCounter「Processor\% Processor Time」
/// - 内存：GlobalMemoryStatusEx
/// - GPU：PerformanceCounter「GPU Engine」（Win10+），失败时尝试 nvidia-smi；均不可用则如实返回 null
/// - 磁盘：PerformanceCounter「LogicalDisk」+ DriveInfo
/// - 网络：NetworkInterface 统计差分
/// - 温度：WMI MSAcpi_ThermalZoneTemperature（多数消费级主板不支持，不支持时如实说明）
/// </summary>
public class PerformanceCollector : IPerformanceMonitor
{
    private PerformanceCounter? _cpuCounter;
    private bool _gpuUnavailable;
    private bool _tempUnavailable;
    private int _intervalMs = 2000;
    private System.Timers.Timer? _timer;
    // 采样防重入：采样耗时时丢弃本次 tick，避免并发采样叠加导致 CPU 占用翻倍
    private int _sampling;

    public event EventHandler<PerformanceSnapshot>? Sampled;

    public bool IsRunning => _timer != null;

    /// <summary>是否有可见订阅者。没有订阅者时应 Stop()，避免空转。</summary>
    public bool HasSubscribers => Sampled != null;

    public void SetIntervalMs(int intervalMs)
    {
        _intervalMs = Math.Clamp(intervalMs, 500, 60_000);
        if (_timer != null) _timer.Interval = _intervalMs;
    }

    public void Start()
    {
        if (_timer != null) return;
        // CPU 计数器需要一次预热采样
        try
        {
            _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total", readOnly: true);
            _cpuCounter.NextValue();
        }
        catch (Exception) { _cpuCounter = null; }

        _timer = new System.Timers.Timer(_intervalMs) { AutoReset = true };
        _timer.Elapsed += async (_, _) =>
        {
            // 上一次采样未结束则直接跳过本次，杜绝并发叠加
            if (Interlocked.CompareExchange(ref _sampling, 1, 0) != 0) return;
            try
            {
                var snap = await SampleAsync().ConfigureAwait(false);
                Sampled?.Invoke(this, snap);
            }
            catch (Exception) { /* 单次采样失败不影响后续 */ }
            finally { Interlocked.Exchange(ref _sampling, 0); }
        };
        _timer.Start();
    }

    public void Stop()
    {
        _timer?.Stop();
        _timer?.Dispose();
        _timer = null;
    }

    public async Task<SystemHardwareInfo> GetHardwareInfoAsync(CancellationToken ct = default)
    {
        var info = new SystemHardwareInfo
        {
            MachineName = Environment.MachineName,
            Is64Bit = Environment.Is64BitOperatingSystem,
        };
        var os = Environment.OSVersion;
        info.OsVersion = os.VersionString;
        info.OsBuild = os.Version.Build.ToString();
        info.MemoryTotalBytes = GetTotalMemory();

        await Task.Run(() =>
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT Caption, Version, BuildNumber, LastBootUpTime FROM Win32_OperatingSystem");
                foreach (var o in searcher.Get())
                {
                    info.OsName = o["Caption"]?.ToString() ?? "";
                    info.OsBuild = o["BuildNumber"]?.ToString() ?? info.OsBuild;
                    if (DateTime.TryParse(o["LastBootUpTime"]?.ToString(), out var boot)) info.BootTime = boot;
                    break;
                }
            }
            catch (Exception) { }

            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    "SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor");
                foreach (var o in searcher.Get())
                {
                    info.CpuName = o["Name"]?.ToString() ?? "";
                    break;
                }
            }
            catch (Exception) { }

            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher("SELECT Name, AdapterRAM FROM Win32_VideoController");
                foreach (var o in searcher.Get())
                {
                    var name = o["Name"]?.ToString() ?? "";
                    if (!string.IsNullOrEmpty(name)) info.GpuNames.Add(name);
                }
            }
            catch (Exception) { }

            foreach (var d in GetDiskInfos()) info.Disks.Add(d);
        }, ct);
        return info;
    }

    public async Task<PerformanceSnapshot> SampleAsync(CancellationToken ct = default)
    {
        var snap = new PerformanceSnapshot();

        // CPU
        if (_cpuCounter != null)
        {
            try { snap.Cpu.UsagePercent = Math.Clamp(_cpuCounter.NextValue(), 0, 100); }
            catch (Exception) { }
        }
        snap.Cpu.LogicalCores = Environment.ProcessorCount;

        // 内存
        var mem = GetMemoryStatus();
        snap.Memory = new MemoryInfo
        {
            TotalBytes = mem.ullTotalPhys,
            AvailableBytes = mem.ullAvailPhys,
            UsedBytes = mem.ullTotalPhys - mem.ullAvailPhys,
        };

        // GPU（异步探测一次失败即标记，后续不再尝试，控制开销）
        if (!_gpuUnavailable)
            snap.Gpu = await SampleGpuAsync().ConfigureAwait(false);

        // 磁盘
        snap.Disks = GetDiskInfos();

        // 网络
        snap.Networks = SampleNetworks();

        // 温度（探测一次）
        if (!_tempUnavailable)
        {
            var t = await SampleTemperatureAsync().ConfigureAwait(false);
            if (t == null) _tempUnavailable = true;
            else snap.Cpu.TemperatureC = t;
        }

        return snap;
    }

    // ---------------- GPU ----------------
    // 计数器对象创建开销很大（独立显卡实例可达数十个），
    // 缓存实例名与计数器对象，只读 NextValue()；失效时才重建。
    private string[]? _gpuInstanceNames;
    private PerformanceCounter[]? _gpuCounters;
    private PerformanceCounter[]? _gpuMemCounters;

    private async Task<GpuInfo> SampleGpuAsync()
    {
        try
        {
            _gpuCounters ??= EnsureGpuCounters();
            var names = _gpuInstanceNames;
            if (_gpuCounters.Length == 0 || names == null) throw new InvalidOperationException("无 GPU Engine 计数器实例");
            double sum = 0;
            foreach (var c in _gpuCounters) sum += c.NextValue();
            if (sum <= 0)
            {
                // 多数驱动在首个采样返回 0，再采一次
                await Task.Delay(200).ConfigureAwait(false);
                sum = 0;
                foreach (var c in _gpuCounters) sum += c.NextValue();
            }
            var gpu = new GpuInfo
            {
                UsagePercent = Math.Clamp(sum, 0, 100),
                Source = "性能计数器 GPU Engine",
                Name = WmiGpuName(),
            };
            // 显存（GPU Adapter Memory 计数器：专用内存）
            try
            {
                ulong dedicated = 0;
                _gpuMemCounters ??= new PerformanceCounterCategory("GPU Adapter Memory").GetInstanceNames()
                    .Select(inst => new PerformanceCounter("GPU Adapter Memory", "Dedicated Usage", inst, readOnly: true))
                    .ToArray();
                foreach (var c in _gpuMemCounters)
                {
                    try { dedicated = Math.Max(dedicated, (ulong)c.NextValue()); }
                    catch (InvalidOperationException)
                    {
                        // 计数器失效：清空缓存，下次采样重建
                        _gpuMemCounters = null;
                        break;
                    }
                }
                gpu.MemoryUsedBytes = dedicated;
            }
            catch (Exception) { }
            return gpu;
        }
        catch (Exception)
        {
            // nvidia-smi 回退
            try
            {
                var psi = new ProcessStartInfo("nvidia-smi",
                    "--query-gpu=name,utilization.gpu,memory.total,memory.used --format=csv,noheader,nounits")
                {
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true,
                };
                using var p = Process.Start(psi)!;
                var line = await p.StandardOutput.ReadLineAsync().ConfigureAwait(false);
                p.WaitForExit(3000);
                if (!string.IsNullOrEmpty(line))
                {
                    var parts = line.Split(',');
                    if (parts.Length >= 4)
                    {
                        return new GpuInfo
                        {
                            Name = parts[0].Trim(),
                            UsagePercent = Math.Clamp(double.Parse(parts[1].Trim()), 0, 100),
                            MemoryTotalBytes = (ulong)(double.Parse(parts[2].Trim()) * 1024 * 1024),
                            MemoryUsedBytes = (ulong)(double.Parse(parts[3].Trim()) * 1024 * 1024),
                            Source = "nvidia-smi",
                        };
                    }
                }
            }
            catch (Exception) { }
            _gpuUnavailable = true;
            return new GpuInfo { Name = WmiGpuName(), Source = "不可用（本机无 GPU 利用率计数器）" };
        }
    }

    private string _gpuNameCache = string.Empty;
    private string WmiGpuName()
    {
        if (!string.IsNullOrEmpty(_gpuNameCache)) return _gpuNameCache;
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher("SELECT Name FROM Win32_VideoController");
            foreach (var o in searcher.Get())
            {
                _gpuNameCache = o["Name"]?.ToString() ?? "";
                break;
            }
        }
        catch (Exception) { }
        return _gpuNameCache;
    }

    /// <summary>枚举并缓存 GPU 利用率计数器（首次构造后复用）。</summary>
    private PerformanceCounter[] EnsureGpuCounters()
    {
        try
        {
            var cat = new PerformanceCounterCategory("GPU Engine");
            _gpuInstanceNames = cat.GetInstanceNames()
                .Where(n => n.Contains("engtype_3D", StringComparison.OrdinalIgnoreCase)
                         || n.Contains("engtype_Graphics", StringComparison.OrdinalIgnoreCase)
                         || n.Contains("engtype_CopyVid", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            var list = new List<PerformanceCounter>();
            foreach (var n in _gpuInstanceNames)
            {
                try { list.Add(new PerformanceCounter("GPU Engine", "Utilization Percentage", n, readOnly: true)); }
                catch (Exception) { }
            }
            return list.ToArray();
        }
        catch (Exception)
        {
            return Array.Empty<PerformanceCounter>();
        }
    }

    // ---------------- 温度 ----------------
    private async Task<double?> SampleTemperatureAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                using var searcher = new System.Management.ManagementObjectSearcher(
                    @"root\WMI", "SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature");
                foreach (var o in searcher.Get())
                {
                    if (o["CurrentTemperature"] != null)
                    {
                        var v = Convert.ToDouble(o["CurrentTemperature"]);
                        return v / 10.0 - 273.15; // 0.1K -> °C
                    }
                }
                return (double?)null;
            }
            catch (Exception) { return null; }
        }).ConfigureAwait(false);
    }

    // ---------------- 磁盘 ----------------
    // 磁盘 IO 计数器按盘符缓存，避免每次采样都新建（DriveInfo 仍需实时读取容量）
    private readonly Dictionary<string, PerformanceCounter> _diskReadCounters = new();
    private readonly Dictionary<string, PerformanceCounter> _diskWriteCounters = new();

    private List<DiskInfo> GetDiskInfos()
    {
        var list = new List<DiskInfo>();
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady || drive.DriveType is not (DriveType.Fixed or DriveType.Removable)) continue;
                var di = new DiskInfo
                {
                    DriveLetter = drive.Name,
                    VolumeLabel = drive.VolumeLabel,
                    TotalBytes = (ulong)drive.TotalSize,
                    FreeBytes = (ulong)drive.AvailableFreeSpace,
                };
                // 读写字节/秒计数器（按盘符实例，缓存复用）
                try
                {
                    var inst = drive.Name[..2];
                    if (!_diskReadCounters.TryGetValue(inst, out var rc))
                    {
                        rc = new PerformanceCounter("LogicalDisk", "Disk Read Bytes/sec", inst, readOnly: true);
                        _diskReadCounters[inst] = rc;
                    }
                    if (!_diskWriteCounters.TryGetValue(inst, out var wc))
                    {
                        wc = new PerformanceCounter("LogicalDisk", "Disk Write Bytes/sec", inst, readOnly: true);
                        _diskWriteCounters[inst] = wc;
                    }
                    di.ReadBytesPerSec = rc.NextValue();
                    di.WriteBytesPerSec = wc.NextValue();
                }
                catch (Exception) { }
                list.Add(di);
            }
        }
        catch (Exception) { }
        return list;
    }

    // ---------------- 网络 ----------------
    private List<NetworkTrafficInfo> SampleNetworks()
    {
        var now = DateTime.UtcNow;
        var list = new List<NetworkTrafficInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
            var st = nic.GetIPv4Statistics();
            // 用适配器 Id 做差分
            var prev = _prevNet.TryGetValue(nic.Id, out var p) ? p : default;
            if (prev != default)
            {
                var dt = (now - prev.time).TotalSeconds;
                if (dt > 0.3)
                {
                    list.Add(new NetworkTrafficInfo
                    {
                        AdapterName = nic.Name,
                        UploadBytesPerSec = Math.Max(0, (double)(st.BytesSent - (long)prev.sent) / dt),
                        DownloadBytesPerSec = Math.Max(0, (double)(st.BytesReceived - (long)prev.recv) / dt),
                    });
                }
            }
            _prevNet[nic.Id] = (now, (ulong)st.BytesSent, (ulong)st.BytesReceived);
        }
        // 清理过期记录
        var expired = _prevNet.Where(x => (now - x.Value.time).TotalMinutes > 5).Select(x => x.Key).ToList();
        foreach (var k in expired) _prevNet.Remove(k);
        return list;
    }

    private readonly Dictionary<string, (DateTime time, ulong sent, ulong recv)> _prevNet = new();

    // ---------------- Win32 API ----------------
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    private static MEMORYSTATUSEX GetMemoryStatus()
    {
        var m = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        GlobalMemoryStatusEx(ref m);
        return m;
    }

    public static ulong GetTotalMemory() => GetMemoryStatus().ullTotalPhys;
}
