# 发布脚本：自包含 x64 发布 + 便携版 zip + Inno Setup 安装包 + SHA256SUMS
# 版本号唯一来源：Directory.Build.props 的 <Version>
$ErrorActionPreference = 'Stop'
$root = Split-Path $MyInvocation.MyCommand.Path
Set-Location $root

[xml]$props = Get-Content Directory.Build.props
$ver = $props.Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
if (-not $ver) { throw "Directory.Build.props 中未找到 <Version>" }
Write-Host "版本：$ver" -ForegroundColor Cyan

Write-Host "== 1. Release 全量构建 + 测试 ==" -ForegroundColor Cyan
dotnet build PcSecurityCenter.slnx -c Release
if ($LASTEXITCODE -ne 0) { throw "build failed" }
dotnet test tests/PcSecurityCenter.Tests/PcSecurityCenter.Tests.csproj -c Release --no-build
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

Write-Host "== 2. 自包含发布 ==" -ForegroundColor Cyan
dotnet publish src/PcSecurityCenter.App/PcSecurityCenter.App.csproj -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=false -p:IncludeNativeLibrariesForSelfExtract=true `
    -o publish/selfcontained
if ($LASTEXITCODE -ne 0) { throw "publish failed" }

Write-Host "== 3. 便携版 zip ==" -ForegroundColor Cyan
$zip = "publish/PcSecurityCenter-Portable-$ver.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "publish/selfcontained/*" -DestinationPath $zip -CompressionLevel Optimal
# 附带文档（含 LICENSE）
$tmp = "publish/_portable_doc"
New-Item -ItemType Directory -Force $tmp | Out-Null
Copy-Item installer/使用说明.md installer/更新日志.md installer/LICENSES.md LICENSE $tmp -Force
Compress-Archive -Path "$tmp/*" -DestinationPath $zip -Update
Remove-Item $tmp -Recurse -Force
Write-Host "  $zip"

Write-Host "== 4. Inno Setup 安装包 ==" -ForegroundColor Cyan
$iscc = $null
$cmd = Get-Command iscc -ErrorAction SilentlyContinue
if ($cmd) { $iscc = $cmd.Source }
foreach ($p in @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe")) {
    if (-not $iscc -and (Test-Path $p)) { $iscc = $p }
}
if (-not $iscc) { throw "ISCC.exe 未找到，请先安装 Inno Setup 6" }
& $iscc "/DAppVersion=$ver" installer/PcSecurityCenter.iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }

Write-Host "== 5. SHA256SUMS ==" -ForegroundColor Cyan
$setup = Get-ChildItem publish/installer -Filter "PcSecurityCenter-Setup-$ver.exe" | Select-Object -First 1
if (-not $setup) { throw "未找到安装包产物" }
$sums = @(
    (Get-FileHash $setup.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + "  " + $setup.Name,
    (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() + "  " + (Split-Path $zip -Leaf)
) -join "`n"
Set-Content -Path "publish/SHA256SUMS.txt" -Value $sums -Encoding ascii
Write-Host "  publish/SHA256SUMS.txt"

Write-Host "== 6. 产物清单 ==" -ForegroundColor Green
Get-ChildItem publish -File | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB,1)}}
Get-ChildItem publish/installer -File -ErrorAction SilentlyContinue | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB,1)}}
Write-Host "发布完成。" -ForegroundColor Green
