using System.Security.Cryptography;
using System.Text.Json;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Core.FileAnalysis;
using PcSecurityCenter.Core.Utils;

namespace PcSecurityCenter.Platform.Security;

/// <summary>
/// 隔离区实现（本工具自有仓库，用于 SmartRisk 等引擎标记的文件）：
/// - 文件 AES-256 加密存入隔离库（无密钥无法还原内容）；
/// - 每条记录保存原文件 SHA256 与密文 SHA256（完整性校验，防篡改/逃逸）；
/// - 恢复前校验密文哈希，恢复后校验原哈希，双重验证；
/// - 原路径必须经过 PathSafety 校验（拒绝越界路径）；
/// - Defender 检出的威胁优先走 Defender 官方隔离（Remove-MpThreat）。
/// </summary>
public class QuarantineService : IQuarantineService
{
    private readonly string _vaultDir;
    private readonly string _recordsFile;
    private readonly byte[] _key;
    private readonly object _lock = new();

    public QuarantineService(string? baseDir = null)
    {
        _vaultDir = baseDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "PcSecurityCenter", "Quarantine");
        Directory.CreateDirectory(_vaultDir);
        _recordsFile = Path.Combine(_vaultDir, "index.records.json");
        _key = LoadOrCreateKey(Path.Combine(_vaultDir, "vault.key"));
    }

    public string VaultDirectory => _vaultDir;

    private static byte[] LoadOrCreateKey(string keyPath)
    {
        if (File.Exists(keyPath))
        {
            var data = File.ReadAllBytes(keyPath);
            if (data.Length == 32) return data;
        }
        var key = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(keyPath, key);
        try { File.SetAttributes(keyPath, FileAttributes.Hidden); } catch (Exception) { }
        return key;
    }

    private List<QuarantineRecord> LoadRecords()
    {
        lock (_lock)
        {
            try
            {
                if (!File.Exists(_recordsFile)) return new List<QuarantineRecord>();
                var json = File.ReadAllText(_recordsFile);
                return JsonSerializer.Deserialize<List<QuarantineRecord>>(json) ?? new();
            }
            catch (Exception) { return new List<QuarantineRecord>(); }
        }
    }

    private void SaveRecords(List<QuarantineRecord> records)
    {
        lock (_lock)
        {
            var json = JsonSerializer.Serialize(records, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_recordsFile, json);
        }
    }

    public async Task<QuarantineEntry> QuarantineFileAsync(string filePath, string reason, string engine, ThreatSeverity severity)
    {
        // 只接受绝对路径：相对路径一律拒绝（防 CWD 依赖与路径混淆攻击）
        if (string.IsNullOrWhiteSpace(filePath) || !Path.IsPathRooted(filePath) || filePath.IndexOf('\0') >= 0)
            throw new ArgumentException("必须提供绝对路径");
        var full = PathSafety.NormalizeAbsolute(filePath)
            ?? throw new ArgumentException("非法路径");
        if (!File.Exists(full)) throw new FileNotFoundException("文件不存在", full);
        // 防误伤：系统关键目录根级文件禁止隔离（临时目录中的除外）
        if (PathSafety.IsCriticalSystemPath(full) && !full.StartsWith(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("系统关键目录中的文件不允许由本工具直接隔离");

        var originalSha = await FileAnalyzer.ComputeHashAsync(full, SHA256.Create()).ConfigureAwait(false);
        var entry = new QuarantineEntry
        {
            OriginalPath = full,
            FileName = Path.GetFileName(full),
            SizeBytes = new FileInfo(full).Length,
            OriginalSha256 = originalSha,
            QuarantinedAt = DateTime.Now,
            Reason = reason,
            Engine = engine,
            Severity = severity,
        };
        entry.VaultFileName = $"q_{entry.Id:N}.qtn";

        // AES 加密（IV 前置于密文）
        var cipher = await Task.Run(() =>
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.GenerateIV();
            using var encryptor = aes.CreateEncryptor();
            using var src = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var ms = new MemoryStream();
            ms.Write(aes.IV, 0, aes.IV.Length);
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write, leaveOpen: true))
                src.CopyTo(cs, 64 * 1024);
            return ms.ToArray();
        }).ConfigureAwait(false);

        var vaultPath = Path.Combine(_vaultDir, entry.VaultFileName);
        await File.WriteAllBytesAsync(vaultPath, cipher).ConfigureAwait(false);
        try { File.SetAttributes(vaultPath, FileAttributes.Hidden); } catch (Exception) { }

        var record = new QuarantineRecord
        {
            Entry = entry,
            CipherSha256 = Convert.ToHexString(SHA256.HashData(cipher)),
        };
        var records = LoadRecords();
        records.Add(record);
        SaveRecords(records);

        // 删除原文件（目标已校验）
        File.Delete(full);
        Serilog.Log.Information("已隔离文件 {File} -> 隔离库 {Vault}，原因：{Reason}（引擎 {Engine}）",
            full, entry.VaultFileName, reason, engine);
        return entry;
    }

    public Task<List<QuarantineEntry>> ListAsync() =>
        Task.FromResult(LoadRecords().Select(r => r.Entry).ToList());

    public async Task<bool> RestoreAsync(Guid entryId, string? restoreDir = null)
    {
        var records = LoadRecords();
        var rec = records.FirstOrDefault(r => r.Entry.Id == entryId);
        if (rec == null) return false;
        var vaultPath = Path.Combine(_vaultDir, rec.Entry.VaultFileName);
        if (!File.Exists(vaultPath)) return false;

        var cipher = await File.ReadAllBytesAsync(vaultPath).ConfigureAwait(false);

        // 完整性校验 1：密文哈希必须与隔离时一致，防止隔离库被篡改
        var cipherSha = Convert.ToHexString(SHA256.HashData(cipher));
        if (!string.Equals(cipherSha, rec.CipherSha256, StringComparison.OrdinalIgnoreCase))
        {
            Serilog.Log.Warning("隔离区完整性校验失败：{File}（记录 {Id}），拒绝恢复", vaultPath, entryId);
            return false;
        }

        var plain = await Task.Run(() =>
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using var src = new MemoryStream(cipher);
            var iv = new byte[16];
            if (src.Read(iv, 0, iv.Length) != iv.Length) throw new InvalidOperationException("隔离数据损坏");
            aes.IV = iv;
            using var decryptor = aes.CreateDecryptor();
            using var cs = new CryptoStream(src, decryptor, CryptoStreamMode.Read);
            using var ms = new MemoryStream();
            cs.CopyTo(ms, 64 * 1024);
            return ms.ToArray();
        }).ConfigureAwait(false);

        // 完整性校验 2：解密内容哈希必须与原始文件一致
        var plainSha = Convert.ToHexString(SHA256.HashData(plain));
        if (!string.Equals(plainSha, rec.Entry.OriginalSha256, StringComparison.OrdinalIgnoreCase))
        {
            Serilog.Log.Warning("隔离恢复内容校验失败：{Id}，拒绝写回", entryId);
            return false;
        }

        var targetDir = restoreDir != null ? PathSafety.NormalizeInside(restoreDir, ".") : null;
        var targetPath = targetDir != null
            ? Path.Combine(targetDir, rec.Entry.FileName)
            : rec.Entry.OriginalPath;

        if (File.Exists(targetPath))
            targetPath += $".restored_{DateTime.Now:yyyyMMddHHmmss}";
        Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
        await File.WriteAllBytesAsync(targetPath, plain).ConfigureAwait(false);
        Serilog.Log.Information("隔离文件已恢复：{Id} -> {Path}", entryId, targetPath);
        return true;
    }

    public Task<bool> DeleteAsync(Guid entryId)
    {
        var records = LoadRecords();
        var rec = records.FirstOrDefault(r => r.Entry.Id == entryId);
        if (rec == null) return Task.FromResult(false);
        var vaultPath = Path.Combine(_vaultDir, rec.Entry.VaultFileName);
        if (File.Exists(vaultPath))
        {
            // 安全覆写后删除，防止内容残留
            try
            {
                var len = new FileInfo(vaultPath).Length;
                using var fs = new FileStream(vaultPath, FileMode.Open, FileAccess.Write);
                var zeros = new byte[64 * 1024];
                long remain = len;
                while (remain > 0)
                {
                    var n = (int)Math.Min(remain, zeros.Length);
                    fs.Write(zeros, 0, n);
                    remain -= n;
                }
            }
            catch (Exception) { }
            File.Delete(vaultPath);
        }
        records.Remove(rec);
        SaveRecords(records);
        Serilog.Log.Information("隔离记录已删除：{Id}（{File}）", entryId, rec.Entry.OriginalPath);
        return Task.FromResult(true);
    }

    private sealed class QuarantineRecord
    {
        public QuarantineEntry Entry { get; set; } = new();
        public string CipherSha256 { get; set; } = string.Empty;
    }
}
