using System.Text.Json;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using Serilog;

namespace PcSecurityCenter.Data.Configuration;

/// <summary>
/// 统一配置管理（JSON，位于 %APPDATA%\PcSecurityCenter）。
/// 不收集任何隐私数据；哈希查询等联网功能默认关闭。
/// </summary>
public class ConfigService : IConfigService
{
    private static readonly string DefaultConfigFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "PcSecurityCenter", "config.json");

    private readonly string _configFile;
    private readonly SemaphoreSlim _saveGate = new(1, 1);

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public AppConfigData Current { get; private set; } = new();

    /// <summary>允许注入配置文件路径（默认用户目录；测试与便携版可覆盖）。</summary>
    public ConfigService(string? configFile = null)
    {
        _configFile = configFile ?? DefaultConfigFile;
    }

    public Task LoadAsync()
    {
        try
        {
            if (File.Exists(_configFile))
            {
                var json = File.ReadAllText(_configFile);
                Current = JsonSerializer.Deserialize<AppConfigData>(json, JsonOpts) ?? new AppConfigData();
            }
        }
        catch (Exception ex)
        {
            Serilog.Log.Warning(ex, "配置读取失败，使用默认配置");
            Current = new AppConfigData();
        }
        return Task.CompletedTask;
    }

    public async Task<bool> SaveAsync()
    {
        await _saveGate.WaitAsync();
        string? temporary = null;
        try
        {
            var target = Path.GetFullPath(_configFile);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            var json = JsonSerializer.Serialize(Current, JsonOpts);
            temporary = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
            await File.WriteAllTextAsync(temporary, json);
            // 同目录提交，保存失败时原配置仍可读。
            if (File.Exists(target)) File.Replace(temporary, target, null);
            else File.Move(temporary, target);
            return true;
        }
        catch (Exception ex)
        {
            Serilog.Log.Warning(ex, "配置保存失败");
            return false;
        }
        finally
        {
            if (temporary != null)
                try { File.Delete(temporary); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            _saveGate.Release();
        }
    }
}

/// <summary>统一路径管理（禁止在业务代码里硬编码系统路径）。</summary>
public static class AppPaths
{
    private static readonly string Root = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PcSecurityCenter");

    public static string DataRoot => Root;
    public static string LogsDir => Path.Combine(Root, "logs");
    public static string DbFile => Path.Combine(Root, "security.db");
    public static string ReportsDir => Path.Combine(Root, "reports");
    public static string QuarantineDir => Path.Combine(Root, "Quarantine");

    public static void EnsureAll()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(LogsDir);
        Directory.CreateDirectory(ReportsDir);
    }
}

/// <summary>Serilog 日志初始化。</summary>
public static class LoggingSetup
{
    public static void Initialize(AppConfigData? config = null)
    {
        AppPaths.EnsureAll();
        var retainedDays = Math.Clamp(config?.MaxLogDays ?? 30, 1, 3650);
        Serilog.Log.CloseAndFlush();
        Serilog.Log.Logger = new Serilog.LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.File(
                Path.Combine(AppPaths.LogsDir, "psec-.log"),
                rollingInterval: Serilog.RollingInterval.Day,
                retainedFileCountLimit: retainedDays,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {Message:lj}{NewLine}{Exception}",
                shared: true)
            .CreateLogger();
    }
}
