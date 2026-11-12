# PcSecurityCenter 项目进化报告

执行日期：2026-11-12（Asia/Shanghai）  
项目类型：Windows 桌面安全软件  
工程根目录：`E:\移动云盘同步盘\Scan the computer for viruses\PcSecurityCenter`  
版本基线：`1.2.2`（`Directory.Build.props`）

## 1. 原始情况

项目使用 C#、.NET 10、WPF、CommunityToolkit.Mvvm、SQLite、Serilog、LiveCharts2、PowerShell、Windows API/WMI 和 Microsoft Defender 官方接口。工程已包含扫描、实时防护、隔离、系统安全、维护、网络、性能、启动项、软件管理、文件分析、报告和更新中心。

工作区原先通过 OneDrive 保留了大量“仅联机”占位文件，导致本地没有完整源码且没有可用 .NET SDK。执行过程中只在本项目下恢复了远程快照 `fd66b4b74602a3b769be64768779c4e78f480099` 的缺失文件，保留了现有工作区改动，没有重置分支或删除用户文件。

## 2. 竞品研究

已完成 GitHub 候选检索 18 个，深度查看 5 个仓库的 README、工程结构和可见源码/测试布局。完整清单、许可证、研究证据和采用/放弃理由见 [research.json](research.json)。研究重点包括：

- BleachBit：清理前预览、可审计清理定义、测试和 Windows 构建流程。
- SophiApp：按用户目标分组设置、可逆操作、权限/能力说明和本地化。
- ClamAV-GUI：扫描状态、取消、隔离、定义更新、实时监控和平台边界。
- Hexnest：测量式清理、系统/网络监控、平台条件编译和便携交付。
- Soterios：首次运行引导、隐私模式、报告、更新校验和发布披露。

没有复制第三方代码、图标或资源，也没有引入新的杀毒引擎。GitHub API 匿名请求在后续元数据查询时触发限流，因此报告省略易变化的 star 数；源代码浅克隆和仓库地址已保存在 `.evolution/research_sources`。

## 3. 实际完成的改进

### P1：真实功能与正确性

- 扫描排除路径现在从配置进入 `ScanContext.ExcludedPaths`，由 SmartRisk 在文件级过滤；支持换行或分号分隔，并忽略非法路径。
- 下载/临时目录的脚本规则按内容证据分级：命中下载、持久化或隐藏执行证据升级为 High；无证据的 `.bat/.cmd/.ps1/.js` 降为 Low/Notice；开发目录中的 `.js` 不再制造高噪音提示。
- 实时防护使用 `(PID, StartTime)` 识别进程，避免 PID 复用误判；只清理已经退出的 PID，不再超过阈值时整体清空；临时进程事件按路径和规则去抖，常见构建工具记录为 Info。
- 更新中心启动时只检查版本，不自动下载；下载由用户明确点击触发；应用更新前检查扫描状态，扫描运行时显示会中断扫描的确认框；移除了 60 秒自动重启倒计时。
- `ConfigService.SaveAsync` 返回成功/失败，设置页面在写入失败时显示可解释错误。
- `MaxLogDays` 接入 Serilog 文件保留数量；启动读取配置后重新初始化日志。
- `AutoUpdateDefenderSignatures` 现在有真实行为：启用后，启动时若病毒库超过 24 小时未更新，调用 Defender 官方更新接口。
- 删除设置页中没有实现后端的哈希信誉查询开关和 API Key 输入，避免向用户承诺不存在的联网能力；文件分析隐私说明同步更新。
- 配置默认版本与当前构建版本统一为 1.2.2。

### 工程与交付

- 为本次本机发布验证安装了 .NET SDK 10.0.404 和 Inno Setup 6.7.3；它们只用于开发机验证，生产项目没有新增 NuGet 依赖。
- `publish.ps1` 已在 Windows PowerShell 5.1 与 PowerShell 7 通过语法解析，并完成一次完整的 Release 构建、测试、自包含发布、便携 ZIP、Inno 安装包和 SHA256 清单生成。
- 生成项目身份、进度、功能差距、研究、测试和最终报告文件。
- 保留现有架构和 Defender 权威判定边界，没有新增第三方依赖。

## 4. 主要修改文件

- `src/PcSecurityCenter.Core/Abstractions/IScanAbstractions.cs`
- `src/PcSecurityCenter.Core/Abstractions/IServiceAbstractions.cs`
- `src/PcSecurityCenter.Core/Models/AppConfigData.cs`
- `src/PcSecurityCenter.Core/Scanning/ScanOrchestrator.cs`
- `src/PcSecurityCenter.Core/Scanning/SmartRiskEngine.cs`
- `src/PcSecurityCenter.Data/Configuration/ConfigService.cs`
- `src/PcSecurityCenter.Platform/Defender/DefenderClient.cs`
- `src/PcSecurityCenter.Platform/Realtime/WindowsRealtimeProtector.cs`
- `src/PcSecurityCenter.App/App.xaml.cs`
- `src/PcSecurityCenter.App/MainWindow.xaml.cs`
- `src/PcSecurityCenter.App/Services/UpdaterService.cs`
- `src/PcSecurityCenter.App/ViewModels/FileAnalysisReportSettingsVMs.cs`
- `src/PcSecurityCenter.App/ViewModels/UpdateViewModel.cs`
- `src/PcSecurityCenter.App/Views/SettingsPage.xaml`
- `tests/PcSecurityCenter.Tests/CoreLogicTests.cs`
- `tests/PcSecurityCenter.Tests/IntegrationTests.cs`

## 5. 依赖变化

生产项目没有新增 NuGet 依赖。测试和构建只使用现有包；本机额外安装的 .NET 10.0.404 SDK 与 Inno Setup 6.7.3 不是应用运行时依赖。

## 6. 测试结果

完整证据见 [test_report.json](test_report.json)。已执行：

- Release 全解决方案构建：0 警告、0 错误。
- 完整测试套件：104/104 通过，0 失败，0 跳过，耗时 2 分 43 秒。
- 新增/相关 SmartRisk 与配置测试：9/9 通过。
- 安全、更新、隔离和工程回归子集：86/86 通过。
- Defender 集成：3/3 通过。
- PowerShell 集成：4/4 通过。
- `publish.ps1` 全链路：构建、全量测试和打包完成；安装包与便携 ZIP 的 SHA256 均与 `publish/SHA256SUMS.txt` 一致，便携 ZIP 包含 350 个条目。

## 7. 评分

评分依据是代码、测试和交付证据，不代表杀毒引擎能力保证。

| 维度 | 改造前 | 当前 | 证据 |
|---|---:|---:|---|
| 功能完整度 | 18/25 | 21/25 | 排除路径、设置保存反馈、Defender 更新行为、更新互斥已落地 |
| UI 与用户体验 | 13/20 | 15/20 | 去除假开关、更新确认、设置状态反馈；尚未做逐页人工验收 |
| 稳定性 | 14/20 | 18/20 | Release 构建与 104 项测试全通过 |
| 架构与代码质量 | 11/15 | 13/15 | 分层保持、配置结果可见、实时进程基线修正 |
| 性能与安全 | 8/10 | 9/10 | 进程去抖、低噪音规则、无新增联网引擎；真实全盘性能未测 |
| 文档与工程交付 | 6/10 | 9/10 | 研究、差距、测试、进度和最终报告齐全 |
| **总分** | **70/100** | **85/100** | **提升 15 分** |

## 8. 未完成事项与风险

- 没有执行真实全盘扫描、真实威胁隔离/清除、安装包安装/回滚和签名更新端到端验证。
- 没有完成 Windows 10 真机、多 DPI、暗色主题和逐页辅助功能人工验收。
- 本地生成的安装包当前为未签名；没有可用签名证书，因此不能视为可发布安装包。
- 尚未执行管理员权限下的安装、回滚、卸载和签名更新端到端验证。
- 更新功能仍依赖真实 GitHub Release 资产；当前没有上传、发布或签名任何构建产物。
- 当前仓库分支已整理为单一 `main`：本地 `main` 与 `origin/main` 均指向 `fd66b4b`，并已配置默认跟踪和推送目标；远程没有其他分支需要删除。
- 工作区仍含用户未提交改动；本次没有提交、推送、打标签或发布。

## 9. 下一阶段建议

1. 在隔离测试机执行 11 项真机验收，重点覆盖 UAC、全盘进度、扫描中更新、真实 Defender 威胁 ID 定点处理。
2. 在提升权限的受控 Windows 测试机执行安装、回滚、卸载和签名校验。
3. 做一次人工 UI 回归：Win10/11、100%/125%/150% 缩放、亮暗主题、无权限和空状态。
4. 再评估是否需要把扫描排除路径同步到 Windows Defender 排除策略；若实现，必须保持显式确认和可撤销记录。

当前交付状态：**代码和自动化验证已完成本批次；发布批准仍待真机与安装包验收。**
