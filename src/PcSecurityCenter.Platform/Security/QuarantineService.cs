using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Core.Utils;

namespace PcSecurityCenter.Platform.Security;

/// <summary>
/// 隔离区实现（本工具自有仓库，用于 SmartRisk 等引擎标记的文件）：
/// - 文件 AES-256-CBC 加密 + HMAC-SHA256 认证（encrypt-then-MAC）存入隔离库，密文被篡改即拒绝恢复；
/// - 主密钥用 DPAPI（CurrentUser）保护存盘，拿到 key 文件也无法还原密钥；
/// - 流式加解密，大文件不整体载入内存；恢复先落临时文件、校验通过再移动到目标位置；
/// - index 原子写 + 备份，损坏时保留现场，绝不静默覆写；
/// - 兼容 v1.0.0 旧格式隔离文件（仍可恢复，沿用旧的哈希校验强度）；
/// - 原路径必须经过 PathSafety 校验（拒绝越界路径）；
/// - Defender 检出的威胁优先走 Defender 官方隔离（Remove-MpThreat）。
/// </summary>
public class QuarantineService : IQuarantineService
{
    private static readonly byte[] VaultMagic = "PSCQTN2"u8.ToArray();
    private const int IvSize = 16;
    private const int TagSize = 32;

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

    // v2 密钥派生：加密与认证各用独立子密钥
    private byte[] EncKey
    {
        get { using var h = new HMACSHA256(_key); return h.ComputeHash("PSCQ-ENC"u8.ToArray()); }
    }

    private byte[] MacKey
    {
        get { using var h = new HMACSHA256(_key); return h.ComputeHash("PSCQ-MAC"u8.ToArray()); }
    }

    private static byte[] LoadOrCreateKey(string keyPath)
    {
        if (File.Exists(keyPath))
        {
            var data = File.ReadAllBytes(keyPath);
            if (data.Length == 32)
            {
                // v1.0.0 旧格式：32 字节明文密钥 → 用 DPAPI 包裹后原地升级，既有隔离数据不受影响
                ProtectKeyFile(keyPath, data);
                return data;
            }
            try
            {
                return Dpapi.Unprotect(data);
            }
            catch (Exception)
            {
                // 密钥文件损坏：保留现场（改名 .bad）再建新钥，绝不静默覆盖
                try { File.Move(keyPath, keyPath + ".bad", overwrite: true); } catch (Exception) { }
                Serilog.Log.Error("隔离区密钥文件损坏，已改名保留为 vault.key.bad；既有隔离条目将无法恢复");
            }
        }
        var key = RandomNumberGenerator.GetBytes(32);
        ProtectKeyFile(keyPath, key);
        return key;
    }

    private static void ProtectKeyFile(string keyPath, byte[] key)
    {
        File.WriteAllBytes(keyPath, Dpapi.Protect(key));
        try { File.SetAttributes(keyPath, FileAttributes.Hidden); } catch (Exception) { }
    }

    private List<QuarantineRecord> LoadRecords()
    {
        lock (_lock)
        {
            if (!File.Exists(_recordsFile)) return new List<QuarantineRecord>();
            string json;
            try { json = File.ReadAllText(_recordsFile); }
            catch (Exception ex)
            {
                Serilog.Log.Error(ex, "隔离区索引读取失败");
                return new List<QuarantineRecord>();
            }
            try
            {
                return JsonSerializer.Deserialize<List<QuarantineRecord>>(json) ?? new();
            }
            catch (Exception ex)
            {
                // 损坏的索引移开保留（供人工恢复），不用空表静默覆写
                var backup = $"{_recordsFile}.corrupt-{DateTime.Now:yyyyMMddHHmmss}";
                try { File.Move(_recordsFile, backup, overwrite: true); } catch (Exception) { }
                Serilog.Log.Error(ex, "隔离区索引损坏，已保留为 {Backup}", Path.GetFileName(backup));
                return new List<QuarantineRecord>();
            }
        }
    }

    private void SaveRecords(List<QuarantineRecord> records)
    {
        lock (_lock)
        {
            var json = JsonSerializer.Serialize(records, new JsonSerializerOptions { WriteIndented = true });
            var tmp = _recordsFile + ".tmp";
            File.WriteAllText(tmp, json);
            if (File.Exists(_recordsFile))
                File.Replace(tmp, _recordsFile, _recordsFile + ".bak");
            else
                File.Move(tmp, _recordsFile);
        }
    }

    public async Task<QuarantineEntry> QuarantineFileAsync(string filePath, string reason, string engine, ThreatSeverity severity)
    {
        // 只接受绝对路径：相对路径一律拒绝（防 CWD 依赖与路径混淆攻击）
        if (string.IsNullOrWhiteSpace(filePath) || !Path.IsPathRooted(filePath) || filePath.IndexOf((char)0) >= 0)
            throw new ArgumentException("必须提供绝对路径");
        var full = PathSafety.NormalizeAbsolute(filePath)
            ?? throw new ArgumentException("非法路径");
        if (!File.Exists(full)) throw new FileNotFoundException("文件不存在", full);
        // 防误伤：系统关键目录根级文件禁止隔离（临时目录中的除外）
        if (PathSafety.IsCriticalSystemPath(full) && !full.StartsWith(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("系统关键目录中的文件不允许由本工具直接隔离");

        var entry = new QuarantineEntry
        {
            OriginalPath = full,
            FileName = Path.GetFileName(full),
            SizeBytes = new FileInfo(full).Length,
            QuarantinedAt = DateTime.Now,
            Reason = reason,
            Engine = engine,
            Severity = severity,
        };
        entry.VaultFileName = $"q_{entry.Id:N}.qtn";

        var vaultPath = Path.Combine(_vaultDir, entry.VaultFileName);
        var tmpPath = vaultPath + ".tmp";
        try
        {
            // 流式加密：单次读取原文同时算出原文 SHA256（消除「哈希与加密两次打开」的 TOCTOU）
            entry.OriginalSha256 = await Task.Run(() => EncryptToFile(full, tmpPath)).ConfigureAwait(false);
            File.Move(tmpPath, vaultPath, overwrite: true);
            try { File.SetAttributes(vaultPath, FileAttributes.Hidden); } catch (Exception) { }
        }
        finally
        {
            try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch (Exception) { }
        }

        var record = new QuarantineRecord
        {
            Entry = entry,
            CipherSha256 = ComputeSha(vaultPath),
        };
        var records = LoadRecords();
        records.Add(record);
        SaveRecords(records);

        // 删除原文件；失败则回滚隔离副本，保持「文件要么在原地、要么在隔离库」的不变式
        try
        {
            File.Delete(full);
        }
        catch (Exception ex)
        {
            records.Remove(record);
            SaveRecords(records);
            try { File.Delete(vaultPath); } catch (Exception) { }
            throw new IOException($"原文件删除失败，隔离已回滚：{ex.Message}", ex);
        }
        Serilog.Log.Information("已隔离文件 {File} -> 隔离库 {Vault}，原因：{Reason}（引擎 {Engine}）",
            full, entry.VaultFileName, reason, engine);
        return entry;
    }

    private static string ComputeSha(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var h = SHA256.Create();
        return Convert.ToHexString(h.ComputeHash(fs)).ToLowerInvariant();
    }

    public Task<List<QuarantineEntry>> ListAsync() =>
        Task.FromResult(LoadRecords().Select(r => r.Entry).ToList());

    /// <summary>流式加密 src 到 dest（v2 格式：magic + IV + 密文 + HMAC 标签），返回原文 SHA256。</summary>
    private string EncryptToFile(string src, string dest)
    {
        using var aes = Aes.Create();
        aes.Key = EncKey;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();

        using var plainHash = SHA256.Create();
        using (var input = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var output = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            output.Write(VaultMagic);
            output.Write(aes.IV);
            using (var encryptor = aes.CreateEncryptor())
            using (var cs = new CryptoStream(output, encryptor, CryptoStreamMode.Write, leaveOpen: true))
            {
                var buffer = new byte[64 * 1024];
                int n;
                while ((n = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    plainHash.TransformBlock(buffer, 0, n, null, 0);
                    cs.Write(buffer, 0, n);
                }
                cs.FlushFinalBlock();
            }
            plainHash.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        }

        // encrypt-then-MAC：标签覆盖 magic + IV + 全部密文，验证失败直接拒绝恢复
        using (var mac = new HMACSHA256(MacKey))
        {
            byte[] tag;
            using (var verify = new FileStream(dest, FileMode.Open, FileAccess.Read, FileShare.Read))
                tag = mac.ComputeHash(verify);
            using var append = new FileStream(dest, FileMode.Append, FileAccess.Write, FileShare.None);
            append.Write(tag);
        }
        return Convert.ToHexString(plainHash.Hash!).ToLowerInvariant();
    }

    public async Task<bool> RestoreAsync(Guid entryId, string? restoreDir = null)
    {
        var records = LoadRecords();
        var rec = records.FirstOrDefault(r => r.Entry.Id == entryId);
        if (rec == null) return false;
        var vaultPath = Path.Combine(_vaultDir, rec.Entry.VaultFileName);
        if (!File.Exists(vaultPath)) return false;

        var tmpPlain = Path.Combine(_vaultDir, $"restore_{entryId:N}.tmp");
        string plainSha;
        try
        {
            plainSha = await Task.Run(() => DecryptToFile(vaultPath, tmpPlain, rec)).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Serilog.Log.Warning("隔离区完整性校验失败：{File}（记录 {Id}），拒绝恢复：{Error}",
                vaultPath, entryId, ex.Message);
            return false;
        }

        try
        {
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
            File.Move(tmpPlain, targetPath, overwrite: true);
            Serilog.Log.Information("隔离文件已恢复：{Id} -> {Path}", entryId, targetPath);
            return true;
        }
        finally
        {
            try { if (File.Exists(tmpPlain)) File.Delete(tmpPlain); } catch (Exception) { }
        }
    }

    /// <summary>流式解密 vault 到临时明文文件，返回明文 SHA256；完整性校验失败抛异常。</summary>
    private string DecryptToFile(string vaultPath, string dest, QuarantineRecord rec)
    {
        using var fs = new FileStream(vaultPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var head = new byte[VaultMagic.Length];
        fs.ReadExactly(head, 0, head.Length);
        var isV2 = head.AsSpan().SequenceEqual(VaultMagic);
        fs.Position = 0;

        if (!isV2)
        {
            // v1.0.0 旧格式（IV + 密文，无认证标签）：按记录中的密文哈希做旧式校验
            if (!string.Equals(ComputeSha(vaultPath), rec.CipherSha256, StringComparison.OrdinalIgnoreCase))
                throw new CryptographicException("密文哈希校验失败（旧格式）");
            var iv1 = new byte[IvSize];
            fs.Position = 0;
            fs.ReadExactly(iv1);
            using var aes1 = Aes.Create();
            aes1.Key = _key; // 旧格式直接使用主密钥
            aes1.IV = iv1;
            aes1.Mode = CipherMode.CBC;
            aes1.Padding = PaddingMode.PKCS7;
            using var dec1 = aes1.CreateDecryptor();
            using var cs1 = new CryptoStream(fs, dec1, CryptoStreamMode.Read);
            return WritePlainAndHash(cs1, dest);
        }

        // v2：先验 HMAC 标签（覆盖 magic+IV+密文），不通过直接拒绝
        var contentLen = fs.Length - TagSize;
        if (contentLen <= VaultMagic.Length + IvSize) throw new CryptographicException("隔离数据长度非法");
        var storedTag = new byte[TagSize];
        fs.Position = contentLen;
        fs.ReadExactly(storedTag);
        using (var h = new HMACSHA256(MacKey))
        {
            fs.Position = 0;
            var computed = h.ComputeHash(new LimitedStream(fs, contentLen));
            if (!CryptographicOperations.FixedTimeEquals(computed, storedTag))
                throw new CryptographicException("HMAC 校验失败（密文被篡改）");
        }

        fs.Position = VaultMagic.Length;
        var iv = new byte[IvSize];
        fs.ReadExactly(iv);
        using var aes = Aes.Create();
        aes.Key = EncKey;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var decryptor = aes.CreateDecryptor();
        using var cs = new CryptoStream(
            new LimitedStream(fs, contentLen - VaultMagic.Length - IvSize), decryptor, CryptoStreamMode.Read);
        return WritePlainAndHash(cs, dest);
    }

    private static string WritePlainAndHash(Stream plain, string dest)
    {
        using var hash = SHA256.Create();
        using var output = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None);
        var buffer = new byte[64 * 1024];
        int n;
        while ((n = plain.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.TransformBlock(buffer, 0, n, null, 0);
            output.Write(buffer, 0, n);
        }
        hash.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return Convert.ToHexString(hash.Hash!).ToLowerInvariant();
    }

    /// <summary>底层流的前 length 字节只读视图（验标签/解密时排除文件尾部的 HMAC 标签）。</summary>
    private sealed class LimitedStream : Stream
    {
        private readonly Stream _inner;
        private readonly long _length;
        private long _remaining;

        public LimitedStream(Stream inner, long length)
        {
            _inner = inner;
            _length = length;
            _remaining = length;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _length;
        public override long Position { get => _length - _remaining; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = _inner.Read(buffer, offset, (int)Math.Min(count, _remaining));
            _remaining -= n;
            return n;
        }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
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

    /// <summary>DPAPI（CurrentUser）保护的密钥存取，替代明文 vault.key。</summary>
    private static class Dpapi
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct DATA_BLOB
        {
            public int cbData;
            public IntPtr pbData;
        }

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptProtectData(
            ref DATA_BLOB pDataIn, string? szDataDescr, IntPtr pOptionalEntropy,
            IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptUnprotectData(
            ref DATA_BLOB pDataIn, IntPtr ppszDataDescr, IntPtr pOptionalEntropy,
            IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr hMem);

        private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;

        public static byte[] Protect(byte[] data) => Transform(data, protect: true);
        public static byte[] Unprotect(byte[] data) => Transform(data, protect: false);

        private static byte[] Transform(byte[] data, bool protect)
        {
            var inBlob = new DATA_BLOB();
            var outBlob = new DATA_BLOB();
            var inPtr = Marshal.AllocHGlobal(data.Length);
            try
            {
                Marshal.Copy(data, 0, inPtr, data.Length);
                inBlob.cbData = data.Length;
                inBlob.pbData = inPtr;
                var ok = protect
                    ? CryptProtectData(ref inBlob, "PcSecurityCenter Quarantine", IntPtr.Zero,
                        IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref outBlob)
                    : CryptUnprotectData(ref inBlob, IntPtr.Zero, IntPtr.Zero,
                        IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref outBlob);
                if (!ok) throw new CryptographicException(Marshal.GetLastWin32Error());
                var result = new byte[outBlob.cbData];
                Marshal.Copy(outBlob.pbData, result, 0, outBlob.cbData);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(inPtr);
                if (outBlob.pbData != IntPtr.Zero) LocalFree(outBlob.pbData);
            }
        }
    }
}
