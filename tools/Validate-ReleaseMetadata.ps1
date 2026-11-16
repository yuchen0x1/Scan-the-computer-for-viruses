<#
.SYNOPSIS
    Checks that user-facing release metadata agrees with Directory.Build.props.

.DESCRIPTION
    Directory.Build.props is the single version source for builds. This check
    catches stale Inno Setup fallbacks and copy-pasted current-release commands
    before a release is packaged. Historical release entries are intentionally
    ignored; only the first/current entry in each document is checked.
#>
[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $Root

function Read-Text([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing release metadata file: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw
}

[xml]$props = Read-Text 'Directory.Build.props'
$version = [string]($props.Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1)
if ([string]::IsNullOrWhiteSpace($version) -or $version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Directory.Build.props contains an invalid <Version>: '$version'"
}

$checks = [System.Collections.Generic.List[string]]::new()
function Assert-Match([string]$Label, [string]$Text, [string]$Pattern) {
    if ($Text -notmatch $Pattern) {
        throw "Release metadata mismatch: $Label (expected version $version)"
    }
    $checks.Add($Label)
}

$iss = Read-Text 'installer/PcSecurityCenter.iss'
Assert-Match 'Inno Setup fallback' $iss ('#define\s+AppVersion\s+"' + [regex]::Escape($version) + '"')

$readme = Read-Text 'README.md'
Assert-Match 'README current heading' $readme ("(?m)^###\s+v$([regex]::Escape($version))\s*[（(]")
Assert-Match 'README release link' $readme ("releases/tag/v$([regex]::Escape($version))")
Assert-Match 'README setup artifact' $readme ("PcSecurityCenter-Setup-$([regex]::Escape($version))\.exe")
Assert-Match 'README portable artifact' $readme ("PcSecurityCenter-Portable-$([regex]::Escape($version))\.zip")
Assert-Match 'README release command' $readme ("gh\s+release\s+create\s+v$([regex]::Escape($version))")

$releaseNotes = Read-Text 'docs/releases/release-notes.md'
Assert-Match 'release notes current heading' $releaseNotes ("(?m)^##\s+v$([regex]::Escape($version))\s+[—-]")

$installerNotes = Read-Text 'installer/更新日志.md'
Assert-Match 'installer notes current heading' $installerNotes ("(?m)^##\s+$([regex]::Escape($version))\s+[（(]")

Write-Host ("Release metadata OK: {0} ({1} checks)" -f $version, $checks.Count) -ForegroundColor Green
