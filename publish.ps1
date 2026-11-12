# 发布脚本：自包含 x64 发布 + 便携版 zip + Inno Setup 安装包 + SHA256SUMS
# 版本号唯一来源：Directory.Build.props 的 <Version>
# 注意：本文件必须以 UTF-8 with BOM 保存，否则 Windows PowerShell 5.1 会把中文按 ANSI 解析而报语法错误。
param(
    [string]$Dotnet = 'dotnet',
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $MyInvocation.MyCommand.Path
Set-Location $root

[xml]$props = Get-Content Directory.Build.props
$ver = $props.Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
if (-not $ver) { throw 'Directory.Build.props 中未找到 <Version>' }
Write-Host "版本：$ver" -ForegroundColor Cyan

# 校验 SDK 可用（避免误用只有运行时的 dotnet.exe）
$sdks = & $Dotnet --list-sdks 2>$null
if ($LASTEXITCODE -ne 0 -or -not ($sdks | Select-String -SimpleMatch '10.0.')) {
    throw "未找到 .NET 10 SDK。请通过 -Dotnet 指定 SDK 路径，或把 SDK 目录加入 PATH。"
}

Write-Host '== 0. 停止正在运行的应用（避免锁定已发布 DLL） ==' -ForegroundColor Cyan
Get-Process PcSecurityCenter.App -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "  停止进程 $($_.Id)"
    Stop-Process -Id $_.Id -Force
}
Start-Sleep -Milliseconds 500

Write-Host '== 1. Release 全量构建 + 测试 ==' -ForegroundColor Cyan
& $Dotnet build PcSecurityCenter.slnx -c Release --nologo
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
if (-not $SkipTests) {
    & $Dotnet test tests/PcSecurityCenter.Tests/PcSecurityCenter.Tests.csproj -c Release --no-build --nologo
    if ($LASTEXITCODE -ne 0) { throw 'tests failed' }
}

Write-Host '== 2. 自包含发布 ==' -ForegroundColor Cyan
# 清空旧产物，防止上一版本残留 DLL 混入安装包
if (Test-Path 'publish/selfcontained') { Remove-Item 'publish/selfcontained' -Recurse -Force }
& $Dotnet publish src/PcSecurityCenter.App/PcSecurityCenter.App.csproj -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=false -p:IncludeNativeLibrariesForSelfExtract=true `
    -o publish/selfcontained --nologo
if ($LASTEXITCODE -ne 0) { throw 'publish failed' }

Write-Host '== 3. 便携版 zip ==' -ForegroundColor Cyan
$zip = "publish/PcSecurityCenter-Portable-$ver.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
$tmp = 'publish/_portable_doc'
if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
New-Item -ItemType Directory -Force $tmp | Out-Null
Copy-Item installer/使用说明.md,installer/更新日志.md,installer/LICENSES.md,LICENSE $tmp -Force
# 先打包程序文件，再把文档并入（避免文档被同名目录结构覆盖）
Compress-Archive -Path 'publish/selfcontained/*' -DestinationPath $zip -CompressionLevel Optimal
Compress-Archive -Path "$tmp/*" -DestinationPath $zip -Update
Remove-Item $tmp -Recurse -Force
Write-Host "  $zip"

Write-Host '== 4. Inno Setup 安装包 ==' -ForegroundColor Cyan
if (-not (Test-Path 'publish/installer')) { New-Item -ItemType Directory -Force 'publish/installer' | Out-Null }
$iscc = $null
$cmd = Get-Command iscc -ErrorAction SilentlyContinue
if ($cmd) { $iscc = $cmd.Source }
foreach ($p in @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
    'C:\Program Files\Inno Setup 6\ISCC.exe')) {
    if (-not $iscc -and (Test-Path $p)) { $iscc = $p }
}
if (-not $iscc) { throw 'ISCC.exe 未找到，请先安装 Inno Setup 6' }
& $iscc "/DAppVersion=$ver" installer/PcSecurityCenter.iss
if ($LASTEXITCODE -ne 0) { throw 'ISCC failed' }

Write-Host '== 5. SHA256SUMS ==' -ForegroundColor Cyan
$setup = Get-ChildItem 'publish/installer' -Filter "PcSecurityCenter-Setup-$ver.exe" | Select-Object -First 1
if (-not $setup) { throw '未找到安装包产物' }
$lines = @(
    ((Get-FileHash $setup.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $setup.Name),
    ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + (Split-Path $zip -Leaf))
)
# LF + UTF-8 无 BOM：兼容 Git Bash 的 sha256sum、自更新器逐行解析与各类校验工具
[IO.File]::WriteAllText(
    (Join-Path $root 'publish/SHA256SUMS.txt'),
    ($lines -join "`n") + "`n",
    (New-Object System.Text.UTF8Encoding($false)))
Write-Host '  publish/SHA256SUMS.txt'

Write-Host '== 6. 产物清单 ==' -ForegroundColor Green
Get-ChildItem 'publish' -File | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB,1)}}
Get-ChildItem 'publish/installer' -File -ErrorAction SilentlyContinue | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB,1)}}
Write-Host '发布完成。' -ForegroundColor Green
