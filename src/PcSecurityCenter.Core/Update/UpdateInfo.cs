using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Xml.Linq;

namespace PcSecurityCenter.Core.Update;

/// <summary>GitHub Release 的单个可下载资源（安装包）。</summary>
public sealed class ReleaseAsset
{
    public string Name { get; set; } = "";
    public string DownloadUrl { get; set; } = "";
    public long Size { get; set; }
    public string ContentType { get; set; } = "";
    /// <summary>可选的发布清单内 SHA-256；存在时无需再次下载 SHA256SUMS。</summary>
    public string Sha256 { get; set; } = "";

    /// <summary>返回可安全落盘的文件名（仅取末段、剔除非法字符）；名称无法安全落盘时返回 null。</summary>
    public string? SafeFileName()
    {
        var name = Name.Replace('/', '\\');
        var last = name.LastIndexOf('\\');
        if (last >= 0) name = name[(last + 1)..];
        name = name.Trim();
        if (name.Length == 0 || name is "." or "..") return null;
        if (name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0) return null;
        return name;
    }
}

/// <summary>一次发布的版本信息（来自 GitHub Releases API）。</summary>
public sealed class ReleaseInfo
{
    public string Tag { get; set; } = "";
    public string Version { get; set; } = "";
    public string Name { get; set; } = "";
    public string ReleasePageUrl { get; set; } = "";
    /// <summary>发布说明（Markdown 原文，作为该版本的更新日志）。</summary>
    public string Notes { get; set; } = "";
    public DateTime PublishedAt { get; set; }
    public bool Prerelease { get; set; }
    public bool Draft { get; set; }
    public string Channel { get; set; } = "stable";
    public bool Mandatory { get; set; }
    public bool SecurityFix { get; set; }
    public string MinSupportedVersion { get; set; } = "";
    public List<ReleaseAsset> Assets { get; set; } = new();

    /// <summary>挑选用于自动更新的安装包资源：优先名称含 "Setup" 的 .exe（Inno 安装程序），
    /// 否则退而求其次取任意 .exe。返回 null 表示没有可用的安装包。</summary>
    public ReleaseAsset? SetupAsset =>
        Assets.FirstOrDefault(a => a.Name.Contains("Setup", StringComparison.OrdinalIgnoreCase)
                                   && a.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        ?? Assets.FirstOrDefault(a => a.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));

    /// <summary>挑选随发布附带的 SHA256 校验和文件（名称含 "sha256"），无则返回 null。</summary>
    public ReleaseAsset? ChecksumsAsset =>
        Assets.FirstOrDefault(a => a.Name.Contains("sha256", StringComparison.OrdinalIgnoreCase)
                                   && (a.Name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)
                                       || a.Name.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase)
                                       || a.Name.Equals("SHA256SUMS", StringComparison.OrdinalIgnoreCase)));
}

/// <summary>SHA256SUMS 类校验和文件的解析（"hex 文件名" 每行一条，兼容 '*' 前缀的二进制标记）。</summary>
public static class ChecksumFile
{
    /// <summary>解析校验和文件内容，返回 文件名 → 小写十六进制哈希 的映射；格式非法的行跳过。</summary>
    public static Dictionary<string, string> Parse(string text)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r').Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            var hash = parts[0].Trim();
            if (hash.Length != 64 || hash.Any(c => !Uri.IsHexDigit(c))) continue;
            var file = parts[1].TrimStart('*').Replace('/', '\\');
            var last = file.LastIndexOf('\\');
            if (last >= 0) file = file[(last + 1)..];
            if (file.Length == 0) continue;
            map[file] = hash.ToLowerInvariant();
        }
        return map;
    }
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
            ReleasePageUrl = e.Str("html_url"),
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
                    Sha256 = a.Str("sha256"),
                });
            }
        }
        return r;
    }

    /// <summary>解析 GitHub Releases Atom feed。该来源不受匿名 REST API 配额影响。</summary>
    public static List<ReleaseInfo> ParseAtomFeed(string xml)
    {
        var result = new List<ReleaseInfo>();
        var doc = XDocument.Parse(xml, LoadOptions.None);
        var ns = doc.Root?.Name.Namespace ?? XNamespace.None;
        foreach (var entry in doc.Root?.Elements(ns + "entry") ?? Enumerable.Empty<XElement>())
        {
            var pageUrl = entry.Elements(ns + "link")
                .FirstOrDefault(e => string.Equals((string?)e.Attribute("rel"), "alternate", StringComparison.OrdinalIgnoreCase))
                ?.Attribute("href")?.Value ?? "";
            var tag = ExtractTag(pageUrl);
            if (tag.Length == 0)
            {
                var id = (string?)entry.Element(ns + "id") ?? "";
                tag = id[(id.LastIndexOf('/') + 1)..];
            }

            var title = (string?)entry.Element(ns + "title") ?? tag;
            var notesHtml = (string?)entry.Element(ns + "content") ?? "";
            var updated = (string?)entry.Element(ns + "updated") ?? (string?)entry.Element(ns + "published") ?? "";
            DateTime.TryParse(updated, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var publishedAt);

            result.Add(new ReleaseInfo
            {
                Tag = tag,
                Version = VersionUtility.ParseVersion(tag)?.ToString() ?? tag,
                Name = WebUtility.HtmlDecode(title),
                Notes = HtmlToText(notesHtml),
                ReleasePageUrl = pageUrl,
                PublishedAt = publishedAt,
                Channel = "stable",
                Prerelease = tag.Contains('-', StringComparison.Ordinal),
            });
        }
        return result;
    }

    /// <summary>解析发布工作流生成的静态 update.json 清单。</summary>
    public static List<ReleaseInfo> ParseUpdateManifest(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var e = doc.RootElement;
        if (e.ValueKind != JsonValueKind.Object) return new List<ReleaseInfo>();

        var tag = e.Str("tag");
        var version = e.Str("version");
        var release = new ReleaseInfo
        {
            Tag = string.IsNullOrWhiteSpace(tag) ? version : tag,
            Version = VersionUtility.ParseVersion(version.Length > 0 ? version : tag)?.ToString() ?? version,
            Name = e.Str("name"),
            Notes = e.Str("releaseNotes"),
            ReleasePageUrl = e.Str("releaseUrl"),
            Channel = string.IsNullOrWhiteSpace(e.Str("channel")) ? "stable" : e.Str("channel"),
            Mandatory = e.Bool("mandatory"),
            SecurityFix = e.Bool("securityFix"),
            MinSupportedVersion = e.Str("minSupportedVersion"),
            Prerelease = e.Bool("prerelease"),
            Draft = e.Bool("draft"),
        };
        var date = e.Str("releaseDate");
        if (DateTime.TryParse(date, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var publishedAt))
            release.PublishedAt = publishedAt;

        if (e.TryGetProperty("assets", out var assets) && assets.ValueKind == JsonValueKind.Array)
        {
            foreach (var a in assets.EnumerateArray())
            {
                release.Assets.Add(new ReleaseAsset
                {
                    Name = a.Str("name"),
                    DownloadUrl = a.Str("downloadUrl"),
                    Size = a.Long("size"),
                    ContentType = a.Str("contentType"),
                    Sha256 = a.Str("sha256"),
                });
            }
        }
        return new List<ReleaseInfo> { release };
    }

    private static string ExtractTag(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return "";
        var marker = "/releases/tag/";
        var index = uri.AbsolutePath.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        return index < 0 ? "" : Uri.UnescapeDataString(uri.AbsolutePath[(index + marker.Length)..]).Trim('/');
    }

    private static string HtmlToText(string html)
    {
        if (string.IsNullOrWhiteSpace(html)) return "";
        var text = html
            .Replace("<li>", "\n- ", StringComparison.OrdinalIgnoreCase)
            .Replace("</li>", "", StringComparison.OrdinalIgnoreCase)
            .Replace("</p>", "\n", StringComparison.OrdinalIgnoreCase)
            .Replace("</h1>", "\n", StringComparison.OrdinalIgnoreCase)
            .Replace("</h2>", "\n", StringComparison.OrdinalIgnoreCase)
            .Replace("</h3>", "\n", StringComparison.OrdinalIgnoreCase)
            .Replace("<br>", "\n", StringComparison.OrdinalIgnoreCase)
            .Replace("<br/>", "\n", StringComparison.OrdinalIgnoreCase)
            .Replace("<br />", "\n", StringComparison.OrdinalIgnoreCase);
        text = System.Text.RegularExpressions.Regex.Replace(text, "<[^>]+>", "");
        text = WebUtility.HtmlDecode(text);
        return string.Join("\n", text.Replace("\r\n", "\n").Split('\n').Select(x => x.TrimEnd()).Where(x => x.Trim().Length > 0)).Trim();
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
