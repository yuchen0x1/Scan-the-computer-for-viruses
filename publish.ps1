# 发布脚本：自包含 x64 发布 + 便携版 zip + Inno Setup 安装包
$ErrorActionPreference = 'Stop'
$root = Split-Path $MyInvocation.MyCommand.Path
Set-Location $root

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
$zip = "publish/PcSecurityCenter-Portable-1.0.0.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "publish/selfcontained/*" -DestinationPath $zip -CompressionLevel Optimal
# 附带文档
$tmp = "publish/_portable_doc"
New-Item -ItemType Directory -Force $tmp | Out-Null
Copy-Item installer/使用说明.md installer/更新日志.md installer/LICENSES.md $tmp -Force
Compress-Archive -Path "$tmp/*" -DestinationPath $zip -Update
Remove-Item $tmp -Recurse -Force
Write-Host "  $zip"

Write-Host "== 4. Inno Setup 安装包 ==" -ForegroundColor Cyan
$iscc = "C:\Users\lenmo\AppData\Local\Programs\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) { $iscc = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" }
if (-not (Test-Path $iscc)) { $iscc = "C:\Program Files\Inno Setup 6\ISCC.exe" }
if (-not (Test-Path $iscc)) { throw "ISCC.exe 未找到，请先安装 Inno Setup 6" }
& $iscc installer/PcSecurityCenter.iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed" }

Write-Host "== 5. 产物清单 ==" -ForegroundColor Green
Get-ChildItem publish -File | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB,1)}}
Get-ChildItem publish/installer -File -ErrorAction SilentlyContinue | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB,1)}}
Write-Host "发布完成。" -ForegroundColor Green
