param(
    [Parameter(Mandatory = $true)][string]$SourceUtf8Text,
    [Parameter(Mandatory = $true)][string]$OutRtf
)

# 生成符合 RTF 规范的简体中文许可证文件：
# - 头部声明 \ansicpg936（GBK 代码页）
# - 所有非 ASCII 字节写成 \'xx 十六进制转义
# - RTF 控制字符 \ { } 转义，段落结束写入 \par

$lines = [IO.File]::ReadAllLines($SourceUtf8Text, [Text.Encoding]::UTF8)
$gbk = [Text.Encoding]::GetEncoding(936)

function ConvertTo-RtfEscaped([string]$text) {
    $bytes = $gbk.GetBytes($text)
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) {
        if ($b -ge 0x80) {
            # 非 ASCII 必须按字节转义，否则 RichEdit 按 ANSI 解出乱码
            [void]$sb.Append([char]0x5C)
            [void]$sb.Append([char]0x27)
            [void]$sb.Append(('{0:x2}' -f $b))
        }
        elseif ($b -eq 0x5C -or $b -eq 0x7B -or $b -eq 0x7D) {
            # RTF 控制字符需反斜杠转义
            [void]$sb.Append([char]0x5C)
            [void]$sb.Append([char]$b)
        }
        else {
            [void]$sb.Append([char]$b)
        }
    }
    return $sb.ToString()
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.Append('{\rtf1\ansi\ansicpg936\deff0{\fonttbl{\f0 Microsoft YaHei UI;}}\fs16' + "`r`n")

for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    if ([string]::IsNullOrWhiteSpace($line)) {
        [void]$sb.Append('\par ')
    }
    elseif ($line.StartsWith('# ')) {
        [void]$sb.Append('\b ' + (ConvertTo-RtfEscaped $line.Substring(2)) + '\b0 ')
    }
    else {
        [void]$sb.Append((ConvertTo-RtfEscaped $line))
    }
    [void]$sb.Append('\par ')
}
[void]$sb.Append('}')

[IO.File]::WriteAllText($OutRtf, $sb.ToString(), [Text.Encoding]::ASCII)

$info = Get-Item -LiteralPath $OutRtf
"Wrote $($info.FullName) ($($info.Length) bytes)"
