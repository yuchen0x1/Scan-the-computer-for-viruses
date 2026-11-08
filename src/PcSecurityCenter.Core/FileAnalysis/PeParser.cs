namespace PcSecurityCenter.Core.FileAnalysis;

/// <summary>PE 文件解析结果（只读头部信息，不执行文件内容）。</summary>
public class PeInfo
{
    public bool IsPe { get; set; }
    public string Machine { get; set; } = string.Empty;
    public bool Is64Bit { get; set; }
    public int SectionCount { get; set; }
    public List<string> SectionNames { get; set; } = new();
    public List<string> Imports { get; set; } = new();
    public bool HasDigitalSignatureDirectory { get; set; }
    public DateTime? CompileTimeUtc { get; set; }
    public bool IsDotNet { get; set; }
    public string Error { get; set; } = string.Empty;
}

/// <summary>
/// 轻量 PE 头解析器（纯只读解析，用于文件分析页展示 PE 基本信息）。
/// 解析 DOS 头 → NT 头 → 可选头 → 节表 → 导入目录。
/// </summary>
public static class PeParser
{
    private sealed record SectionEntry(string Name, uint VirtualAddress, uint VirtualSize, uint PointerToRawData, uint SizeOfRawData);

    public static PeInfo Parse(string filePath)
    {
        var info = new PeInfo();
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            Parse(fs, info);
        }
        catch (Exception ex)
        {
            info.Error = ex.Message;
        }
        return info;
    }

    public static void Parse(Stream stream, PeInfo info)
    {
        using var br = new BinaryReader(stream, System.Text.Encoding.ASCII, leaveOpen: true);
        if (stream.Length < 64) { info.Error = "文件太小，不是 PE"; return; }

        // DOS 头
        if (br.ReadUInt16() != 0x5A4D) { info.Error = "缺少 MZ 标记"; return; }
        stream.Position = 0x3C;
        int peOffset = br.ReadInt32();
        if (peOffset <= 0 || peOffset + 24 > stream.Length) { info.Error = "PE 头偏移无效"; return; }

        stream.Position = peOffset;
        if (br.ReadUInt32() != 0x00004550) { info.Error = "缺少 PE 签名"; return; }
        info.IsPe = true;
        long coffStart = stream.Position; // COFF 头起始（PE 签名之后）

        // COFF 头（20 字节）：Machine(2) NumberOfSections(2) TimeDateStamp(4)
        //                   PointerToSymbolTable(4) NumberOfSymbols(4) SizeOfOptionalHeader(2) Characteristics(2)
        ushort machine = br.ReadUInt16();
        info.Machine = machine switch
        {
            0x014c => "x86 (I386)",
            0x8664 => "x64 (AMD64)",
            0xAA64 => "ARM64",
            0x01c4 => "ARMNT",
            _ => $"0x{machine:X4}",
        };
        ushort numberOfSections = br.ReadUInt16();
        info.SectionCount = numberOfSections;
        uint timeStamp = br.ReadUInt32();
        if (timeStamp > 631152000 && timeStamp < 4102444800)
            info.CompileTimeUtc = DateTimeOffset.FromUnixTimeSeconds(timeStamp).UtcDateTime;
        stream.Position = coffStart + 16; // SizeOfOptionalHeader 位于 COFF 头内偏移 16
        ushort sizeOfOptionalHeader = br.ReadUInt16();

        // 可选头起始于 COFF 头之后
        long optHeaderStart = coffStart + 20;
        stream.Position = optHeaderStart;
        ushort optMagic = br.ReadUInt16();
        if (optMagic == 0x20B) info.Is64Bit = true;
        else if (optMagic != 0x10B) { info.Error = "未知可选头格式"; return; }

        // 节表位置 = 可选头之后
        long sectionTable = optHeaderStart + sizeOfOptionalHeader;

        // 读取节表
        var sections = new List<SectionEntry>();
        for (int i = 0; i < numberOfSections; i++)
        {
            long basePos = sectionTable + i * 40;
            if (basePos + 40 > stream.Length) break;
            var nameBytes = ReadBytesAt(stream, basePos, 8);
            var name = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
            var raw = ReadBytesAt(stream, basePos + 8, 32);
            uint virtualSize = BitConverter.ToUInt32(raw, 0);
            uint virtualAddress = BitConverter.ToUInt32(raw, 4);
            uint sizeOfRawData = BitConverter.ToUInt32(raw, 8);
            uint pointerToRawData = BitConverter.ToUInt32(raw, 12);
            sections.Add(new SectionEntry(name, virtualAddress, virtualSize, pointerToRawData, sizeOfRawData));
            info.SectionNames.Add(name);
        }

        // 数据目录起始（自可选头起）：PE32+ = 0x70，PE32 = 0x60
        long ddStart = optHeaderStart + (optMagic == 0x20B ? 0x70 : 0x60);
        if (ddStart + 16 * 8 > stream.Length) { info.Error = "数据目录越界"; return; }

        // 4 号 = 证书（安全表）
        var certRaw = ReadBytesAt(stream, ddStart + 4 * 8, 8);
        uint certSize = BitConverter.ToUInt32(certRaw, 4);
        info.HasDigitalSignatureDirectory = certSize > 0;

        // 14 号 = COM 描述符（.NET）
        var comRaw = ReadBytesAt(stream, ddStart + 14 * 8, 8);
        uint comSize = BitConverter.ToUInt32(comRaw, 4);
        info.IsDotNet = comSize > 0;

        // 1 号 = 导入表
        var impRaw = ReadBytesAt(stream, ddStart + 1 * 8, 8);
        uint importVa = BitConverter.ToUInt32(impRaw, 0);
        uint importSize = BitConverter.ToUInt32(impRaw, 4);
        if (importVa > 0 && importSize > 0)
        {
            long importOffset = RvaToOffset(sections, importVa);
            if (importOffset > 0)
                ParseImports(stream, importOffset, sections, info);
        }
    }

    private static byte[] ReadBytesAt(Stream stream, long position, int count)
    {
        var buf = new byte[count];
        stream.Position = position;
        stream.ReadExactly(buf, 0, count);
        return buf;
    }

    private static long RvaToOffset(List<SectionEntry> sections, uint rva)
    {
        foreach (var s in sections)
        {
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData))
                return s.PointerToRawData + (rva - s.VirtualAddress);
        }
        return -1;
    }

    private static void ParseImports(Stream stream, long importOffset, List<SectionEntry> sections, PeInfo info)
    {
        try
        {
            int count = 0;
            long entryPos = importOffset;
            while (count < 2048)
            {
                if (entryPos + 20 > stream.Length) break;
                var entry = ReadBytesAt(stream, entryPos, 20);
                uint originalFirstThunk = BitConverter.ToUInt32(entry, 0);
                uint nameRva = BitConverter.ToUInt32(entry, 12);
                uint firstThunk = BitConverter.ToUInt32(entry, 16);
                if (nameRva == 0 && firstThunk == 0 && originalFirstThunk == 0) break; // 结束符

                uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
                long nameOffset = RvaToOffset(sections, nameRva);
                if (nameOffset > 0 && nameOffset < stream.Length)
                {
                    var dll = ReadAsciiZ(stream, nameOffset, 256);
                    if (!string.IsNullOrWhiteSpace(dll)) info.Imports.Add(dll);
                }
                entryPos += 20;
                count++;
            }
        }
        catch (Exception) { /* 导入解析失败不影响整体 */ }
    }

    private static string ReadAsciiZ(Stream stream, long position, int max)
    {
        stream.Position = position;
        var bytes = new List<byte>(max);
        for (int i = 0; i < max; i++)
        {
            if (stream.Position >= stream.Length) break;
            int b = stream.ReadByte();
            if (b <= 0) break;
            bytes.Add((byte)b);
        }
        return System.Text.Encoding.ASCII.GetString(bytes.ToArray());
    }
}

/// <summary>文件熵计算（判定加壳/加密内容的辅助指标，仅作提示不作为判定依据）。</summary>
public static class EntropyCalculator
{
    /// <summary>计算数据流的香农熵（比特/字节，0-8）。</summary>
    public static double Compute(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> freq = stackalloc int[256];
        foreach (var b in data) freq[b]++;
        double entropy = 0;
        foreach (var f in freq)
        {
            if (f == 0) continue;
            double p = (double)f / data.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    /// <summary>计算文件采样区段的熵（头部 64KB + 中部 64KB + 尾部 64KB），避免读入超大文件。</summary>
    public static async Task<double> ComputeSampledAsync(string filePath, CancellationToken ct = default)
    {
        return await Task.Run(() =>
        {
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var len = fs.Length;
                if (len == 0) return 0.0;
                int window = (int)Math.Min(64 * 1024, len);
                var buffer = new byte[window];
                double total = 0; int samples = 0;
                foreach (var offset in new long[] { 0, Math.Max(0, len / 2 - window / 2), Math.Max(0, len - window) })
                {
                    ct.ThrowIfCancellationRequested();
                    fs.Position = offset;
                    var read = fs.Read(buffer, 0, buffer.Length);
                    total += Compute(buffer.AsSpan(0, read));
                    samples++;
                }
                return samples > 0 ? total / samples : 0;
            }
            catch (Exception) { return 0.0; }
        }, ct);
    }
}
