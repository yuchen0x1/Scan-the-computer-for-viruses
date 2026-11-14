using PcSecurityCenter.Platform.Maintenance;
using Xunit;

namespace PcSecurityCenter.Tests;

/// <summary>图标缓存白名单：删除范围绝不允许外溢到缓存目录之外。</summary>
public class IconCacheServiceTests
{
    private const string Base = @"C:\Users\test\AppData\Local";
    private const string ExplorerDir = Base + @"\Microsoft\Windows\Explorer";

    [Theory]
    [InlineData(Base + @"\IconCache.db", true)]                        // 旧版单文件缓存
    [InlineData(ExplorerDir + @"\iconcache_16.db", true)]              // 新版分库
    [InlineData(ExplorerDir + @"\iconcache_idx.db", true)]
    [InlineData(ExplorerDir + @"\ICONCACHE_WIDE.DB", true)]            // 大小写不敏感
    [InlineData(ExplorerDir + @"\thumbcache_16.db", false)]            // 缩略图缓存不在白名单（前缀不符）
    [InlineData(ExplorerDir + @"\evil.db", false)]                     // Explorer 目录内非 iconcache 文件
    [InlineData(Base + @"\iconcache_16.db", false)]                    // 根目录下的分库式文件名：拒绝（只允许精确 IconCache.db）
    [InlineData(@"C:\Windows\System32\iconcache_16.db", false)]        // 目录不在白名单
    [InlineData(Base + @"\IconCache.db.bak", false)]                   // 扩展名不符
    [InlineData(Base + @"\data\IconCache.db", false)]                  // 子目录：拒绝
    [InlineData("", false)]
    public void IsIconCacheFile_WhitelistOnly(string path, bool expected)
        => Assert.Equal(expected, IconCachePaths.IsIconCacheFile(path, Base));

    [Fact]
    public void IsIconCacheFile_NullOrWhitespace_ReturnsFalse()
    {
        Assert.False(IconCachePaths.IsIconCacheFile(null!, Base));
        Assert.False(IconCachePaths.IsIconCacheFile("   ", Base));
    }

    [Fact]
    public void IsIconCacheFile_InvalidPath_ReturnsFalse()
        => Assert.False(IconCachePaths.IsIconCacheFile(@"C:\bad\path\:" + "\0", Base));

    [Fact]
    public void EnumerateCacheFiles_AllResultsPassWhitelist()
    {
        // 在真实机器上枚举：缓存文件可能不存在（返回空），但绝不允许返回白名单之外的文件。
        var files = IconCachePaths.EnumerateCacheFiles();
        Assert.All(files, f => Assert.True(IconCachePaths.IsIconCacheFile(f.FullName),
            $"白名单外文件混入：{f.FullName}"));
    }
}
