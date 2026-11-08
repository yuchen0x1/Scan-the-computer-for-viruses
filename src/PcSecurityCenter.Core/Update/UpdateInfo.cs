using System.Globalization;
using System.Text.Json;

namespace PcSecurityCenter.Core.Update;

/// <summary>GitHub Release 的单个可下载资源（安装包）。</summary>
public sealed class ReleaseAsset
{
    public string Name { get; set; } = "";
    public string DownloadUrl { get; set; } = "";
    public long Size { get; set; }
    public string ContentType { get; set; } = "";
}

/// <summary>一次发布的版本信息（来自 GitHub Releases API）。</summary>
public sealed class ReleaseInfo
{
    public string Tag { get; set; } = "";
    public string Version { get; set; } = "";
    public string Name { get; set; } = "";
    /// <summary>发布说明（Markdown 原文，作为该版本的更新日志）。</summary>
    public string Notes { get; set; } = "";
    public DateTime PublishedAt { get; set; }
    public bool Prerelease { get; set; }
    public bool Draft { get; set; }
    public List<ReleaseAsset> Assets { get; set; } = new();

    /// <summary>挑选用于自动更新的安装包资源：优先名称含 "Setup" 的 .exe（Inno 安装程序），
    /// 否则退而求其次取任意 .exe。返回 null 表示没有可用的安装包。</summary>
    public ReleaseAsset? SetupAsset =>
        Assets.FirstOrDefault(a => a.Name.Contains("Setup", StringComparison.OrdinalIgnoreCase)
                                   && a.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        ?? Assets.FirstOrDefault(a => a.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
}

/// <summary>版本号解析与比较工具（与 GitHub tag 形如 "v1.2.3" / "1.2.3" / "v1.2.3-beta" 兼容）。</summary>
public static class VersionUtility
{
    /// <summary>从各种版本字符串解析出 <see cref="Version"/>；无法解析时返回 null。</summary>
    public static Version? ParseVersion(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = raw!.Trim();
        if (s.Length > 0 && (s[0] is 'v' or 'V')) s = s[1..];
        var dash = s.IndexOf('-');
        if (dash >= 0) s = s[..dash];
        var clean = new string(s.Where(c => char.IsDigit(c) || c == '.').ToArray()).Trim('.');
        if (clean.Length == 0) return null;
        return Version.TryParse(clean, out var v) ? v : null;
    }

    /// <summary>比较两个版本。返回值 &lt; 0 表示 latest 更新（有新版本），0 相等，&gt; 0 表示 current 更新。</summary>
    public static int Compare(Version current, Version latest)
    {
        var a = Normalize(current);
        var b = Normalize(latest);
        return a.CompareTo(b);
    }

    private static Version Normalize(Version v) =>
        new(Math.Max(v.Major, 0), Math.Max(v.Minor, 0), Math.Max(v.Build, 0), Math.Max(v.Revision, 0));
}

/// <summary>GitHub Releases API 返回的 JSON 解析（支持单对象与数组两种形态）。</summary>
public static class ReleaseParser
{
    public static List<ReleaseInfo> ParseReleases(string json)
    {
        var result = new List<ReleaseInfo>();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in root.EnumerateArray())
                result.Add(ParseOne(item));
        }
        else if (root.ValueKind == JsonValueKind.Object)
        {
            result.Add(ParseOne(root));
        }
        return result;
    }

    private static ReleaseInfo ParseOne(JsonElement e)
    {
        var r = new ReleaseInfo
        {
            Tag = e.Str("tag_name"),
            Name = e.Str("name"),
            Notes = e.Str("body"),
            Prerelease = e.Bool("prerelease"),
            Draft = e.Bool("draft"),
        };
        if (e.TryGetProperty("published_at", out var pa) && pa.ValueKind == JsonValueKind.String
            && DateTime.TryParse(pa.GetString(), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
        {
            r.PublishedAt = dt;
        }
        r.Version = VersionUtility.ParseVersion(r.Tag)?.ToString() ?? r.Tag;
        if (e.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
        {
            foreach (var a in assets.EnumerateArray())
            {
                r.Assets.Add(new ReleaseAsset
                {
                    Name = a.Str("name"),
                    DownloadUrl = a.Str("browser_download_url"),
                    Size = a.Long("size"),
                    ContentType = a.Str("content_type"),
                });
            }
        }
        return r;
    }
}

internal static class JsonElementExtensions
{
    public static string Str(this JsonElement e, string property)
        => e.TryGetProperty(property, out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() ?? "" : "";

    public static bool Bool(this JsonElement e, string property)
        => e.TryGetProperty(property, out var p) && p.ValueKind == JsonValueKind.True;

    public static long Long(this JsonElement e, string property)
    {
        if (e.TryGetProperty(property, out var p))
        {
            if (p.ValueKind == JsonValueKind.Number) return p.GetInt64();
            if (p.ValueKind == JsonValueKind.String && long.TryParse(p.GetString(), out var l)) return l;
        }
        return 0;
    }
}
