# WPF 扫描页面验证

从仓库根目录运行，需要 Windows 与 .NET 10 SDK。输出目录必须是仓库内全新空目录；工具拒绝复用已有数据。

```powershell
dotnet run --project tools/PcSecurityCenter.UiSmoke -c Release -- artifacts/verification/ui-new
```

验证真实 ScanPage、ScanViewModel、ScanOrchestrator、SmartRiskEngine、SQLite 与配置文件；Defender 使用不可用替身，对话框拒绝危险确认。只在指定目录写入无害样本、临时数据库、隔离库和明暗主题 PNG。窗口在屏幕外承载，用于加载 WPF 模板与绑定；不启动主应用后台防护或更新。

断言包括连续两次扫描仍可见、每次 RunId 的威胁数与汇总一致、覆盖限制落库、搜索与筛选、忙碌状态、Defender 单条处理拒绝后记录仍然保留、无 WPF 绑定警告。截图中的风险来自无害双扩展名测试文件，不是用户机器的检测结论。截图仅覆盖 1080×1200、96 DPI 的扫描页面。

安全回归测试（避免调用真实 Defender / 系统检查）：

```powershell
$env:TEMP = Join-Path (Get-Location) 'artifacts/verification/temp'
$env:TMP = $env:TEMP
New-Item -ItemType Directory -Path $env:TEMP -Force | Out-Null
dotnet test tests/PcSecurityCenter.Tests/PcSecurityCenter.Tests.csproj -c Release --filter 'FullyQualifiedName!~ScanOrchestratorTests&FullyQualifiedName!~DefenderClientIntegrationTests&FullyQualifiedName!~SecurityCheckIntegrationTests'
```

在专用 Windows 测试机上再执行上述被排除的 7 项集成测试和完整应用启动/安装验收。本验证器不证明真实 Defender 扫描、权限提升、安装、更新或其余页面交互均通过。
