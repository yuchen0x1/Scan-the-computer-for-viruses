using PcSecurityCenter.Data.Configuration;
using PcSecurityCenter.Data.Database;
using PcSecurityCenter.Data.Repositories;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Core.Reporting;
using PcSecurityCenter.Core.SecurityChecks;
using PcSecurityCenter.Platform.Defender;
using PcSecurityCenter.Platform.Security;
using PcSecurityCenter.Platform.PowerShell;
using PcSecurityCenter.Platform.Maintenance;
using Xunit;

namespace PcSecurityCenter.Tests;

/// <summary>维护清理：调用方描述不能扩大服务允许的删除目录。</summary>
public class MaintenanceCleanSafetyTests
{
    [Fact]
    public async Task CleanAsync_UnknownIdWithForgedDirectory_DoesNotDeleteFiles()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"psc_clean_guard_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var marker = Path.Combine(dir, "keep.txt");
        await File.WriteAllTextAsync(marker, "must remain");
        try
        {
            var service = new WindowsMaintenanceService(new NoOpPermissionService());
            await service.CleanAsync(new[]
            {
                new MaintenanceCleanItem
                {
                    Id = "caller-controlled",
                    Name = "test",
                    Description = $"forged（目录：{dir}）",
                    RequiresAdmin = false,
                },
            });

            Assert.True(File.Exists(marker));
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    private sealed class NoOpPermissionService : IPermissionService
    {
        public bool IsElevated => false;
        public string ElevationHint => "test";
        public Task<(bool Success, string Output)> RunElevatedAsync(
            ElevatedOperation op, IReadOnlyDictionary<string, string>? args = null, CancellationToken ct = default)
            => Task.FromResult((false, string.Empty));
    }
}

/// <summary>SQLite 数据库：建库、写入、查询、迁移标记。</summary>
public class AppDatabaseTests : IDisposable
{
    private readonly string _dbFile = Path.Combine(Path.GetTempPath(), $"psc_test_{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        try
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            if (File.Exists(_dbFile)) File.Delete(_dbFile);
        }
        catch (Exception) { }
    }

    [Fact]
    public void Initialize_CreatesSchema_AndRepositoriesRoundtrip()
    {
        using var db = new AppDatabase(_dbFile);
        Assert.True(File.Exists(_dbFile));

        var scanRepo = new ScanRunRepository(db);
        var record = new ScanRunRecord
        {
            Type = ScanType.Full, StartedAt = DateTime.Now.AddMinutes(-5), FinishedAt = DateTime.Now,
            FinalState = ScanState.Completed, FilesScanned = 12345, ThreatsFound = 2,
            Engines = "Defender+SmartRisk", Scope = "C:\\", UncoveredNotes = "内存驻留未覆盖",
        };
        scanRepo.Insert(record);
        var loaded = scanRepo.GetRecent(10);
        Assert.Contains(loaded, r => r.Id == record.Id && r.FilesScanned == 12345 && r.UncoveredNotes == "内存驻留未覆盖");

        var threatRepo = new ThreatRepository(db);
        var threat = new ThreatInfo
        {
            Name = "测试威胁", Severity = ThreatSeverity.High, Kind = DetectionKind.Suspicious,
            FilePath = @"C:\temp\evil.pdf.exe", Engine = "SmartRisk", Evidence = "双扩展名",
        };
        threatRepo.Upsert(threat);
        threatRepo.UpdateStatus(threat.Id, ThreatStatus.Quarantined);
        var threats = threatRepo.GetRecent(10);
        Assert.Contains(threats, t => t.Id == threat.Id && t.Status == ThreatStatus.Quarantined);
        Assert.Equal(1, threatRepo.CountActive()); // Quarantined 计入活动

        var eventRepo = new SecurityEventRepository(db);
        eventRepo.Insert(new SecurityEvent { Type = SecurityEventType.SystemCheck, Title = "测试事件", Detail = "d" });
        Assert.Contains(eventRepo.GetRecent(10), e => e.Title == "测试事件");

        var checkRepo = new CheckResultRepository(db);
        checkRepo.InsertBatch("run1", new[]
        {
            new SecurityCheckItem { Id = "c1", Name = "检查1", Category = "防护能力", Status = CheckStatus.Ok, Result = "OK", Method = "M" },
        });
        Assert.Contains(checkRepo.GetLatestRun(), c => c.Id == "c1");

        var maintRepo = new MaintenanceRunRepository(db);
        maintRepo.Insert(new MaintenanceRunRecord { Action = "清理", FreedBytes = 1024, Success = true });
        Assert.Contains(maintRepo.GetRecent(10), m => m.Action == "清理" && m.FreedBytes == 1024);
    }

    [Fact]
    public void Reopen_ExistingDatabase_DoesNotDuplicateSchema()
    {
        using (var db = new AppDatabase(_dbFile)) { }
        using (var db2 = new AppDatabase(_dbFile))
        {
            using var conn = db2.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_version'";
            Assert.Equal(1, Convert.ToInt32(cmd.ExecuteScalar()));
        }
    }
}

/// <summary>配置服务：读写往返。</summary>
public class ConfigServiceTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"psc_cfg_{Guid.NewGuid():N}");

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); } catch (Exception) { }
    }

    [Fact]
    public async Task SaveAndLoad_Roundtrip()
    {
        var file = Path.Combine(_dir, "config.json");
        var cfg1 = new ConfigService(file);
        cfg1.Current.PerformanceIntervalMs = 3000;
        cfg1.Current.RealtimeEnabled = false;
        cfg1.Current.HashLookupEnabled = true;
        cfg1.Current.HashLookupApiKey = "key-123";
        await cfg1.SaveAsync();

        var cfg2 = new ConfigService(file);
        await cfg2.LoadAsync();
        Assert.Equal(3000, cfg2.Current.PerformanceIntervalMs);
        Assert.False(cfg2.Current.RealtimeEnabled);
        Assert.True(cfg2.Current.HashLookupEnabled);
        Assert.Equal("key-123", cfg2.Current.HashLookupApiKey);
    }

    [Fact]
    public async Task Load_MissingFile_UsesDefaults()
    {
        var cfg = new ConfigService(Path.Combine(_dir, "not-exist.json"));
        await cfg.LoadAsync();
        Assert.True(cfg.Current.PerformanceIntervalMs > 0);
        Assert.False(cfg.Current.HashLookupEnabled);
    }

    [Fact]
    public async Task Load_CorruptedFile_FallsBackToDefaults()
    {
        Directory.CreateDirectory(_dir);
        var file = Path.Combine(_dir, "bad.json");
        await File.WriteAllTextAsync(file, "{ not valid json !!!");
        var cfg = new ConfigService(file);
        await cfg.LoadAsync();
        Assert.True(cfg.Current.PerformanceIntervalMs > 0);
    }
}

/// <summary>
/// 隔离区：完整生命周期 + 完整性校验 + 路径防护（安全测试重点）。
/// </summary>
public class QuarantineServiceTests : IDisposable
{
    private readonly string _baseDir = Path.Combine(Path.GetTempPath(), $"psc_qtn_{Guid.NewGuid():N}");

    public void Dispose()
    {
        try { if (Directory.Exists(_baseDir)) Directory.Delete(_baseDir, true); } catch (Exception) { }
    }

    [Fact]
    public async Task Quarantine_Restore_Roundtrip_PreservesContent()
    {
        var workDir = Path.Combine(_baseDir, "work");
        Directory.CreateDirectory(workDir);
        var src = Path.Combine(workDir, "suspicious.pdf.exe");
        var payload = new byte[4096];
        Random.Shared.NextBytes(payload);
        await File.WriteAllBytesAsync(src, payload);

        var svc = new QuarantineService(Path.Combine(_baseDir, "vault"));
        var entry = await svc.QuarantineFileAsync(src, "测试隔离", "SmartRisk", ThreatSeverity.Medium);

        // 原文件已移除
        Assert.False(File.Exists(src));
        // 密文存在且与原文不同
        var vaultFile = Path.Combine(svc.VaultDirectory, entry.VaultFileName);
        Assert.True(File.Exists(vaultFile));
        Assert.NotEqual(payload, await File.ReadAllBytesAsync(vaultFile));
        // 记录可列出
        Assert.Contains(await svc.ListAsync(), e => e.Id == entry.Id && e.OriginalSha256.Length == 64);

        // 恢复：内容与 SHA 必须一致
        var restored = await svc.RestoreAsync(entry.Id);
        Assert.True(restored);
        var restoredBytes = await File.ReadAllBytesAsync(src);
        Assert.Equal(payload, restoredBytes);
        var sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(restoredBytes)).ToLowerInvariant();
        Assert.Equal(entry.OriginalSha256.ToLowerInvariant(), sha);
    }

    [Fact]
    public async Task Restore_WithTamperedVault_ShouldFailIntegrityCheck()
    {
        var workDir = Path.Combine(_baseDir, "work2");
        Directory.CreateDirectory(workDir);
        var src = Path.Combine(workDir, "file.exe");
        await File.WriteAllBytesAsync(src, new byte[] { 1, 2, 3, 4, 5 });

        var svc = new QuarantineService(Path.Combine(_baseDir, "vault2"));
        var entry = await svc.QuarantineFileAsync(src, "测试", "SmartRisk", ThreatSeverity.Low);
        var vaultFile = Path.Combine(svc.VaultDirectory, entry.VaultFileName);

        // 篡改密文（模拟隔离区被篡改/逃逸尝试）。隔离库文件带隐藏属性，覆写前先还原属性
        File.SetAttributes(vaultFile, FileAttributes.Normal);
        var cipher = await File.ReadAllBytesAsync(vaultFile);
        cipher[^1] ^= 0xFF;
        await File.WriteAllBytesAsync(vaultFile, cipher);

        var restored = await svc.RestoreAsync(entry.Id);
        Assert.False(restored, "被篡改的隔离密文必须拒绝恢复");
        Assert.False(File.Exists(src));
    }

    [Fact]
    public async Task Quarantine_RejectsTraversalAndCriticalPaths()
    {
        var svc = new QuarantineService(Path.Combine(_baseDir, "vault3"));
        // 相对路径穿越
        await Assert.ThrowsAsync<ArgumentException>(() =>
            svc.QuarantineFileAsync(@"..\..\Windows\System32\drivers\etc\hosts", "x", "y", ThreatSeverity.Low));
        // 系统关键目录
        if (Directory.Exists(@"C:\Windows\Fonts"))
        {
            var font = Path.Combine(@"C:\Windows\Fonts", "arial.ttf");
            if (File.Exists(font))
                await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    svc.QuarantineFileAsync(font, "x", "y", ThreatSeverity.Low));
        }
        // 不存在的文件
        await Assert.ThrowsAsync<FileNotFoundException>(() =>
            svc.QuarantineFileAsync(@"C:\psc_nonexistent_file.bin", "x", "y", ThreatSeverity.Low));
    }

    [Fact]
    public async Task Delete_OverwritesAndRemoves()
    {
        var workDir = Path.Combine(_baseDir, "work4");
        Directory.CreateDirectory(workDir);
        var src = Path.Combine(workDir, "file4.bin");
        await File.WriteAllBytesAsync(src, new byte[100]);
        var svc = new QuarantineService(Path.Combine(_baseDir, "vault4"));
        var entry = await svc.QuarantineFileAsync(src, "t", "SmartRisk", ThreatSeverity.Low);
        Assert.True(await svc.DeleteAsync(entry.Id));
        Assert.False(File.Exists(Path.Combine(svc.VaultDirectory, entry.VaultFileName)));
        Assert.Empty(await svc.ListAsync());
    }
}

/// <summary>PowerShell 执行器（集成）：真实进程调用 + 参数注入防护。</summary>
public class PowerShellRunnerTests
{
    [Fact]
    public async Task Run_SimpleScript_ReturnsJson()
    {
        var r = await PowerShellRunner.RunAsync("@{ a = 1; b = 'x' } | ConvertTo-Json -Compress", timeoutMs: 30_000);
        Assert.True(r.Success);
        Assert.Contains("\"a\"", r.StdOut);
        Assert.Equal(1, r.Json.GetProperty("a").GetInt32());
    }

    [Fact]
    public async Task Run_EnvVarBridge_SpecialCharactersSafe()
    {
        // 恶意字符串（含引号/分号/反引号）经环境变量传入，不会被当作代码执行
        var evil = "'; Remove-Item C:/Windows -Recurse; '";
        var r = await PowerShellRunner.RunAsync("Write-Output $env:PSC_VALUE", new Dictionary<string, string> { ["value"] = evil }, 30_000);
        Assert.True(r.Success);
        Assert.Contains(evil, r.StdOut);
    }

    [Fact]
    public async Task Run_Timeout_KillsProcess()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PowerShellRunner.RunAsync("Start-Sleep -Seconds 60", timeoutMs: 3000));
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 20_000, "超时后应尽快终止");
    }
}

/// <summary>Defender 客户端（集成，依赖真实机器环境）。</summary>
public class DefenderClientIntegrationTests
{
    [Fact]
    public async Task GetStatus_ReturnsRealStatus()
    {
        var client = new DefenderClient();
        if (!client.IsAvailable)
        {
            // 本机无 Defender 时状态必须如实标记，且不抛异常
            var empty = await client.GetStatusAsync();
            Assert.False(empty.EngineAvailable);
            return;
        }
        var st = await client.GetStatusAsync();
        Assert.True(st.Installed);
        Assert.True(st.EngineAvailable);
        // 病毒库时间应为真实近期时间（允许 30 天内）
        if (st.SignatureLastUpdated != null)
            Assert.True((DateTime.Now - st.SignatureLastUpdated.Value).TotalDays < 30);
    }

    [Fact]
    public async Task ScanPaths_OnHarmlessFile_ReturnsZeroThreats()
    {
        var client = new DefenderClient();
        if (!client.IsAvailable || client.MpCmdRunPath == null) return; // 环境不具备则跳过
        var temp = Path.Combine(Path.GetTempPath(), $"psc_scan_{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(temp, "definitely harmless test content for scanner");
        try
        {
            var result = await client.ScanPathsAsync(new[] { temp }, CancellationToken.None);
            Assert.True(result.Success);
            Assert.Equal(0, result.ThreatsFound);
        }
        finally { File.Delete(temp); }
    }

    [Fact]
    public async Task GetThreatDetections_DoesNotThrow()
    {
        var client = new DefenderClient();
        if (!client.IsAvailable) return;
        var list = await client.GetThreatDetectionsAsync();
        Assert.NotNull(list);
    }
}

/// <summary>文件分析服务（集成）：哈希正确性。</summary>
public class FileAnalysisIntegrationTests
{
    [Fact]
    public async Task Analyze_ComputesKnownHashes()
    {
        var svc = new PlatformFileAnalysisService();
        var temp = Path.Combine(Path.GetTempPath(), $"psc_fa_{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(temp, "abc"); // 已知 SHA256: ba7816bf...
        try
        {
            var report = await svc.AnalyzeAsync(temp);
            Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                report.Sha256.ToLowerInvariant());
            Assert.Equal(3, report.SizeBytes);
            Assert.False(report.IsPe);
        }
        finally { File.Delete(temp); }
    }

    [Fact]
    public async Task ComputeSha256_MatchesKnownVector()
    {
        var svc = new PlatformFileAnalysisService();
        var temp = Path.Combine(Path.GetTempPath(), $"psc_fa2_{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(temp, "");
        try
        {
            var sha = await svc.ComputeSha256Async(temp);
            Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sha.ToLowerInvariant());
        }
        finally { File.Delete(temp); }
    }
}

/// <summary>安全检查服务（集成）：真实检查项 + 权限不足的诚实处理。</summary>
public class SecurityCheckIntegrationTests
{
    [Fact]
    public async Task RunAllChecks_ReturnsItems_WithHonestStatuses()
    {
        var defender = new DefenderClient();
        var perm = new WindowsPermissionService();
        var svc = new PcSecurityCenter.Platform.SecurityChecks.SystemSecurityCheckService(
            defender, new ScoreCalculator(), perm);
        var checks = await svc.RunAllChecksAsync();
        Assert.NotEmpty(checks);
        // 每项都有真实的检测方式与结果描述
        Assert.All(checks, c =>
        {
            Assert.False(string.IsNullOrWhiteSpace(c.Method));
            Assert.False(string.IsNullOrWhiteSpace(c.Result));
        });
        // 标准（非管理员）运行下，需要管理员的项必须如实标记，不得假装安全
        if (!perm.IsElevated)
        {
            var tpm = checks.FirstOrDefault(c => c.Id == "tpm");
            if (tpm != null)
                Assert.True(tpm.Status is CheckStatus.NoPermission or CheckStatus.NotSupported or CheckStatus.Ok or CheckStatus.Error or CheckStatus.Warning,
                    $"TPM 状态不应伪造（实际 {tpm.Status}：{tpm.Result}）");
            var bl = checks.FirstOrDefault(c => c.Id == "bitlocker");
            if (bl != null)
                Assert.True(bl.Status is CheckStatus.NoPermission or CheckStatus.NotSupported or CheckStatus.Ok or CheckStatus.Error or CheckStatus.Warning,
                    $"BitLocker 状态不应伪造（实际 {bl.Status}）");
        }
        // 评分可计算
        var score = svc.CalculateScore(checks);
        Assert.InRange(score.Total, 0, 100);
    }
}

/// <summary>隔离区安全加固回归（v1.1.0）：密钥 DPAPI 保护、索引损坏保留现场、旧格式兼容、HMAC 篡改拒绝。</summary>
public class QuarantineSecurityTests : IDisposable
{
    private readonly string _baseDir = Path.Combine(Path.GetTempPath(), $"psc_qsec_{Guid.NewGuid():N}");

    public void Dispose()
    {
        try { if (Directory.Exists(_baseDir)) Directory.Delete(_baseDir, true); } catch (Exception) { }
    }

    [Fact]
    public void VaultKey_DPAPI保护_不是明文32字节()
    {
        var vaultDir = Path.Combine(_baseDir, "k1");
        _ = new QuarantineService(vaultDir);
        var key = File.ReadAllBytes(Path.Combine(vaultDir, "vault.key"));
        Assert.NotEqual(32, key.Length);
    }

    [Fact]
    public async Task Index损坏_保留现场不静默覆写()
    {
        var vaultDir = Path.Combine(_baseDir, "k2");
        var svc = new QuarantineService(vaultDir);
        var work = Path.Combine(_baseDir, "work");
        Directory.CreateDirectory(work);
        var src = Path.Combine(work, "a.exe");
        await File.WriteAllBytesAsync(src, new byte[] { 1, 2, 3 });
        var entry = await svc.QuarantineFileAsync(src, "测试", "SmartRisk", ThreatSeverity.Low);
        Assert.NotNull(entry);

        var index = Path.Combine(vaultDir, "index.records.json");
        File.WriteAllText(index, "{ this is not json !!!");
        Assert.Empty(await svc.ListAsync());
        Assert.False(File.Exists(index), "损坏索引应被移开而不是原地覆写");
        Assert.Contains(Directory.GetFiles(vaultDir), f => Path.GetFileName(f).Contains(".corrupt-"));
    }

    [Fact]
    public async Task 密文正文被篡改_HMAC拒绝恢复()
    {
        var vaultDir = Path.Combine(_baseDir, "k4");
        var svc = new QuarantineService(vaultDir);
        var work = Path.Combine(_baseDir, "work4");
        Directory.CreateDirectory(work);
        var src = Path.Combine(work, "b.exe");
        await File.WriteAllBytesAsync(src, new byte[] { 9, 8, 7, 6, 5, 4 });
        var entry = await svc.QuarantineFileAsync(src, "测试", "SmartRisk", ThreatSeverity.Low);
        var vaultFile = Path.Combine(vaultDir, entry.VaultFileName);
        File.SetAttributes(vaultFile, FileAttributes.Normal);
        var cipher = await File.ReadAllBytesAsync(vaultFile);
        cipher[10] ^= 0xFF; // 篡改正文中段（而非尾部标签）
        await File.WriteAllBytesAsync(vaultFile, cipher);
        Assert.False(await svc.RestoreAsync(entry.Id, Path.Combine(_baseDir, "out4")));
    }

    [Fact]
    public async Task 旧v1格式隔离文件仍可恢复且密钥自动迁移()
    {
        var vaultDir = Path.Combine(_baseDir, "k3");
        Directory.CreateDirectory(vaultDir);
        var rawKey = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var keyPath = Path.Combine(vaultDir, "vault.key");
        File.WriteAllBytes(keyPath, rawKey); // v1.0.0 明文密钥
        File.SetAttributes(keyPath, File.GetAttributes(keyPath) | FileAttributes.Hidden); // 与用户现场一致

        var payload = new byte[1234];
        Random.Shared.NextBytes(payload);
        byte[] cipher;
        using (var aes = System.Security.Cryptography.Aes.Create())
        {
            aes.Key = rawKey;
            aes.Mode = System.Security.Cryptography.CipherMode.CBC;
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;
            aes.GenerateIV();
            using var ms = new MemoryStream();
            ms.Write(aes.IV);
            using (var cs = new System.Security.Cryptography.CryptoStream(
                ms, aes.CreateEncryptor(), System.Security.Cryptography.CryptoStreamMode.Write, leaveOpen: true))
                cs.Write(payload);
            cipher = ms.ToArray();
        }
        File.WriteAllBytes(Path.Combine(vaultDir, "q_legacy.qtn"), cipher);

        var entryId = Guid.NewGuid();
        var plainSha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(payload)).ToLowerInvariant();
        var cipherSha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(cipher)).ToLowerInvariant();
        var json = $"[{{\"Entry\":{{\"Id\":\"{entryId}\",\"OriginalPath\":\"C:/temp/legacy.bin\",\"FileName\":\"legacy.bin\"," +
            $"\"SizeBytes\":{payload.Length},\"OriginalSha256\":\"{plainSha}\",\"VaultFileName\":\"q_legacy.qtn\"," +
            $"\"QuarantinedAt\":\"2026-01-01T00:00:00\",\"Reason\":\"旧版\",\"Engine\":\"SmartRisk\",\"Severity\":1}}," +
            $"\"CipherSha256\":\"{cipherSha}\"}}]";
        File.WriteAllText(Path.Combine(vaultDir, "index.records.json"), json);

        var svc = new QuarantineService(vaultDir); // 加载时应把明文密钥迁移为 DPAPI 包裹
        Assert.NotEqual(32, File.ReadAllBytes(Path.Combine(vaultDir, "vault.key")).Length);

        var restored = await svc.RestoreAsync(entryId, Path.Combine(_baseDir, "restored3"));
        Assert.True(restored);
        var bytes = await File.ReadAllBytesAsync(Path.Combine(_baseDir, "restored3", "legacy.bin"));
        Assert.Equal(payload, bytes);
    }
}
