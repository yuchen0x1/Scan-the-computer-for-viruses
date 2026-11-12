using PcSecurityCenter.Core.Update;
using Xunit;

namespace PcSecurityCenter.Tests;

public class UpdateTests
{
    [Theory]
    [InlineData("v1.2.3", "1.2.3")]
    [InlineData("1.0.0", "1.0.0")]
    [InlineData("V2.5.1-beta", "2.5.1")]
    [InlineData("v3.0.0-rc.2", "3.0.0")]
    [InlineData("  4.1.0   ", "4.1.0")]
    public void ParseVersion_正常格式_解析成功(string input, string expected)
    {
        var v = VersionUtility.ParseVersion(input);
        Assert.NotNull(v);
        Assert.Equal(expected, v!.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-version")]
    [InlineData(null)]
    public void ParseVersion_非法格式_返回null(string? input)
    {
        Assert.Null(VersionUtility.ParseVersion(input));
    }

    [Theory]
    [InlineData("1.0.0", "1.0.1", -1)]   // latest 更新
    [InlineData("1.0.0", "1.0.0", 0)]    // 相等
    [InlineData("1.0.1", "1.0.0", 1)]    // current 更新
    [InlineData("1.0.0", "1.1.0", -1)]
    [InlineData("2.0.0", "1.9.9", 1)]
    public void Compare_版本比较_符号正确(string current, string latest, int sign)
    {
        var c = VersionUtility.ParseVersion(current)!;
        var l = VersionUtility.ParseVersion(latest)!;
        var r = VersionUtility.Compare(c, l);
        if (sign < 0) Assert.True(r < 0);
        else if (sign > 0) Assert.True(r > 0);
        else Assert.Equal(0, r);
    }

    [Fact]
    public void ParseReleases_单对象_正确解析资产与Setup选择()
    {
        const string json = """
        {
          "tag_name": "v1.0.1",
          "name": "Windows 智能安全卫士 1.0.1",
          "body": "## 修复\n- 修复扫描卡顿",
          "published_at": "2026-11-10T08:00:00Z",
          "prerelease": false,
          "draft": false,
          "assets": [
            { "name": "Windows智能安全卫士-1.0.1-portable.zip", "browser_download_url": "https://x/zip", "size": 100, "content_type": "application/zip" },
            { "name": "Windows智能安全卫士-Setup-1.0.1.exe", "browser_download_url": "https://x/setup.exe", "size": 200, "content_type": "application/octet-stream" }
          ]
        }
        """;

        var list = ReleaseParser.ParseReleases(json);
        Assert.Single(list);
        var r = list[0];
        Assert.Equal("1.0.1", r.Version);
        Assert.Equal(2, r.Assets.Count);
        Assert.NotNull(r.SetupAsset);
        Assert.Equal("Windows智能安全卫士-Setup-1.0.1.exe", r.SetupAsset!.Name);
        Assert.Equal("https://x/setup.exe", r.SetupAsset.DownloadUrl);
        Assert.Equal(new DateTime(2026, 11, 10, 8, 0, 0, DateTimeKind.Utc), r.PublishedAt);
    }

    [Fact]
    public void ParseReleases_数组_按序解析并过滤草稿()
    {
        const string json = """
        [
          { "tag_name": "v1.0.2", "name": "n2", "body": "b2", "draft": false, "prerelease": false, "assets": [] },
          { "tag_name": "v1.0.1", "name": "n1", "body": "b1", "draft": false, "prerelease": false, "assets": [] },
          { "tag_name": "v1.0.0-beta", "name": "nb", "body": "bb", "draft": false, "prerelease": true, "assets": [] }
        ]
        """;

        var list = ReleaseParser.ParseReleases(json);
        Assert.Equal(3, list.Count);
        Assert.Equal("1.0.2", list[0].Version);
        Assert.Equal("1.0.1", list[1].Version);
    }

    [Fact]
    public void ParseAtomFeed_解析版本说明与发布页()
    {
        const string xml = """
        <feed xmlns="http://www.w3.org/2005/Atom">
          <entry>
            <id>tag:github.com,2008:Repository/1/v1.2.3</id>
            <updated>2026-11-12T01:02:03Z</updated>
            <link rel="alternate" href="https://github.com/example/repo/releases/tag/v1.2.3" />
            <title>Windows 安全卫士 v1.2.3</title>
            <content type="html">&lt;h2&gt;修复&lt;/h2&gt;&lt;ul&gt;&lt;li&gt;修复更新检查&lt;/li&gt;&lt;/ul&gt;</content>
          </entry>
        </feed>
        """;

        var release = Assert.Single(ReleaseParser.ParseAtomFeed(xml));
        Assert.Equal("v1.2.3", release.Tag);
        Assert.Equal("1.2.3", release.Version);
        Assert.Contains("修复更新检查", release.Notes);
        Assert.Equal("https://github.com/example/repo/releases/tag/v1.2.3", release.ReleasePageUrl);
        Assert.Equal(new DateTime(2026, 11, 12, 1, 2, 3, DateTimeKind.Utc), release.PublishedAt);
    }

    [Fact]
    public void ParseAtomFeed_预发布标签标记为Prerelease()
    {
        const string xml = """
        <feed xmlns="http://www.w3.org/2005/Atom">
          <entry>
            <id>tag:github.com,2008:Repository/1/v2.0.0-beta.1</id>
            <updated>2026-11-12T01:02:03Z</updated>
            <link rel="alternate" href="https://github.com/example/repo/releases/tag/v2.0.0-beta.1" />
            <title>beta</title>
          </entry>
        </feed>
        """;

        Assert.True(Assert.Single(ReleaseParser.ParseAtomFeed(xml)).Prerelease);
    }

    [Fact]
    public void ParseUpdateManifest_解析资产哈希与策略字段()
    {
        const string json = """
        {
          "version": "1.2.3",
          "tag": "v1.2.3",
          "releaseDate": "2026-11-12T01:02:03Z",
          "releaseNotes": "修复更新链",
          "channel": "stable",
          "mandatory": true,
          "securityFix": true,
          "assets": [
            { "name": "PcSecurityCenter-Setup-1.2.3.exe", "downloadUrl": "https://github.com/x/y/releases/download/v1.2.3/a.exe", "size": 42, "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
            { "name": "SHA256SUMS.txt", "downloadUrl": "https://github.com/x/y/releases/download/v1.2.3/SHA256SUMS.txt" }
          ]
        }
        """;

        var release = Assert.Single(ReleaseParser.ParseUpdateManifest(json));
        Assert.True(release.Mandatory);
        Assert.True(release.SecurityFix);
        Assert.Equal("stable", release.Channel);
        Assert.Equal(42, release.SetupAsset!.Size);
        Assert.Equal("a".PadRight(64, 'a'), release.SetupAsset.Sha256);
        Assert.NotNull(release.ChecksumsAsset);
    }
}

/// <summary>更新链安全（v1.1.0 加固回归）：文件名净化、校验和解析、资源挑选。</summary>
public class UpdateSecurityTests
{
    [Theory]
    [InlineData("../../evil.exe", "evil.exe")]
    [InlineData(@"..\..\evil.exe", "evil.exe")]
    [InlineData("sub/dir/file.exe", "file.exe")]
    [InlineData("PcSecurityCenter-Setup-1.1.0.exe", "PcSecurityCenter-Setup-1.1.0.exe")]
    public void SafeFileName_路径穿越_只保留末段(string raw, string expected)
    {
        Assert.Equal(expected, new ReleaseAsset { Name = raw }.SafeFileName());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("..")]
    [InlineData("bad<name>.exe")]
    public void SafeFileName_非法名称_返回null(string raw)
    {
        Assert.Null(new ReleaseAsset { Name = raw }.SafeFileName());
    }

    [Fact]
    public void ChecksumFile_解析标准行并跳过非法行()
    {
        var map = ChecksumFile.Parse(string.Join('\n',
            "# 注释行",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  PcSecurityCenter-Setup-1.1.0.exe",
            "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210 *portable.zip",
            "nothash  file.exe",
            "1234  bad.exe"));
        Assert.Equal(2, map.Count);
        Assert.Equal("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            map["PcSecurityCenter-Setup-1.1.0.exe"]);
        Assert.Equal("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            map["portable.zip"]);
    }

    [Fact]
    public void ReleaseAssets_挑选安装包与校验和()
    {
        var r = new ReleaseInfo
        {
            Assets =
            {
                new ReleaseAsset { Name = "PcSecurityCenter-Setup-1.1.0.exe" },
                new ReleaseAsset { Name = "SHA256SUMS.txt" },
                new ReleaseAsset { Name = "PcSecurityCenter-Portable-1.1.0.zip" },
            },
        };
        Assert.Equal("SHA256SUMS.txt", r.ChecksumsAsset!.Name);
        Assert.Equal("PcSecurityCenter-Setup-1.1.0.exe", r.SetupAsset!.Name);
    }
}
