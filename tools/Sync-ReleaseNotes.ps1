#requires -Version 7.0
[CmdletBinding()]
param(
    [switch]$Check,
    [string]$Version,
    [string]$OutputFile
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$source = Join-Path $repoRoot 'docs/releases/release-notes.md'
$installerNotes = Join-Path $repoRoot 'installer/更新日志.md'
$history = [IO.File]::ReadAllText($source).Replace("`r`n", "`n")
$entries = [regex]::Matches($history, '(?ms)^## v(?<version>\d+\.\d+\.\d+) — (?<date>\d{4}-\d{2}-\d{2})\n(?<body>.*?)(?=^## |\z)')
if ($entries.Count -eq 0) { throw 'No release entries found.' }
if ([regex]::Matches($history, '(?m)^## ').Count -ne $entries.Count) { throw 'Invalid release heading.' }
$seen = [Collections.Generic.HashSet[string]]::new()
$previous = $null
foreach ($entry in $entries) {
    $number = $entry.Groups['version'].Value
    if (-not $seen.Add($number)) { throw "Duplicate version: $number" }
    if ($null -ne $previous -and [version]$number -ge $previous) { throw 'Versions must be in descending order.' }
    $previous = [version]$number
    [void][datetime]::ParseExact($entry.Groups['date'].Value, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    if ([string]::IsNullOrWhiteSpace($entry.Groups['body'].Value)) { throw "Empty notes: $number" }
}
[xml]$props = [IO.File]::ReadAllText((Join-Path $repoRoot 'Directory.Build.props'))
$currentVersion = [string]$props.Project.PropertyGroup.Version
if ($entries[0].Groups['version'].Value -ne $currentVersion) { throw 'Latest notes must match Directory.Build.props.' }

if ($Version -or $OutputFile) {
    if (-not $Version -or -not $OutputFile -or $Check) { throw 'Use -Version and -OutputFile together, without -Check.' }
    $entry = @($entries | Where-Object { $_.Groups['version'].Value -eq $Version })
    if ($entry.Count -ne 1) { throw "Unknown release: $Version" }
    $destination = [IO.Path]::GetFullPath($OutputFile)
    if (-not $destination.StartsWith($repoRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Release note output must stay inside the repository.'
    }
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
    [IO.File]::WriteAllText($destination, $entry[0].Groups['body'].Value.Trim() + "`n", [Text.UTF8Encoding]::new($false))
    Write-Output "Exported v$Version notes."
    return
}

$builder = [Text.StringBuilder]::new()
[void]$builder.Append("# 更新日志`n`n由 docs/releases/release-notes.md 生成，请修改维护源后运行 tools/Sync-ReleaseNotes.ps1。`n`n")
foreach ($entry in $entries) {
    [void]$builder.Append("## $($entry.Groups['version'].Value) ($($entry.Groups['date'].Value))`n`n")
    [void]$builder.Append($entry.Groups['body'].Value.Trim() + "`n`n")
}
$expected = $builder.ToString().TrimEnd() + "`n"
if ($Check) {
    if (-not [IO.File]::Exists($installerNotes) -or [IO.File]::ReadAllText($installerNotes).Replace("`r`n", "`n") -cne $expected) {
        throw 'Installer notes are stale. Run tools/Sync-ReleaseNotes.ps1.'
    }
    Write-Output "PASS: $($entries.Count) release entries; installer notes synchronized."
} else {
    [IO.File]::WriteAllText($installerNotes, $expected, [Text.UTF8Encoding]::new($false))
    Write-Output "Synchronized $($entries.Count) release entries."
}
