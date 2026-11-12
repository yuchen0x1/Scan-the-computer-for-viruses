# 项目审计与本地升级报告

## 2026-11-12 进化批次补充

本批次已完成并验证以下改动：

- `ScanExclusions` 接入 SmartRisk 扫描上下文；开发目录中的 JS 噪音降低，低信号脚本降为提示级。
- 实时进程基线改为 PID + 启动时间，移除整体清空逻辑，新增临时进程事件去抖和常见构建工具降级。
- 更新启动流程只检查版本，下载由用户明确触发；应用更新前检查扫描状态并要求确认。
- 配置保存返回成功/失败，日志保留天数接入 `MaxLogDays`，Defender 病毒库自动更新开关接入真实官方调用。
- 删除未实现的哈希信誉设置入口，设置页新增日志保留和扫描排除路径配置。
- Release 构建 **0 警告 / 0 错误**；完整测试 **104/104 通过，0 失败，0 跳过**（2026-11-12）。

详细竞品研究、功能差距、测试证据和未完成真机验收见 [.evolution/final_report.md](.evolution/final_report.md)。

审计日期：2026-11-09（Asia/Shanghai）  
项目：Windows 智能安全卫士（PC Security Center）  
审计范围：`C:\Users\lenmo\Desktop\Scan the computer for viruses\PcSecurityCenter`

## 1. 项目现状

这是一个 Windows 10/11 x64 桌面安全管理器，当前版本 1.1.0，采用 .NET 10、WPF、CommunityToolkit.Mvvm、SQLite、Serilog、LiveCharts2、QuestPDF、Windows API/WMI 与 Microsoft Defender 官方接口。不是 Web/API/移动端项目；没有 Android/iOS 子项目，也没有服务端数据库。

解决方案由四层应用项目和一个测试项目组成：

- `src/PcSecurityCenter.Core`：扫描编排、扫描范围、风险规则、路径安全、PE/文件分析、评分、领域模型、报告模型及接口。
- `src/PcSecurityCenter.Platform`：Defender、PowerShell、实时防护、隔离、数字签名、权限、系统安全检查、网络、维护、性能、启动项和已安装软件等 Windows 适配。
- `src/PcSecurityCenter.Data`：SQLite 数据库/仓储、JSON 配置及日志路径初始化。
- `src/PcSecurityCenter.App`：WPF 页面、主题、ViewModel、托盘、更新及 HTML/PDF 导出。
- `tests/PcSecurityCenter.Tests`：核心逻辑、安全、SQLite、Windows 集成和扫描命令测试。
- `installer`、`.github/workflows`、`publish.ps1`：安装包、许可证资料、CI 和本地发布构建流程。

仓库约 110 个已跟踪文件，5 个项目文件、19 个直接 NuGet 引用；没有显式 NuGet 锁文件。工作区起始于 `main`，与 `origin/main` 对齐；起始时仅 `desc.txt` 为用户既有未跟踪文件。本次没有删除垃圾文件或依赖：现存 `obj/`、`publish/` 和工具/发行文件无法安全判定为废弃，按约定保留。

总体判断：功能面完整、分层基本清楚，安全边界意识较强，已有 81 项测试和 Windows CI；仍需关注扫描取消/并发、兼容性告警、自动更新的实际发布链验证，以及若干大范围异常吞并导致的诊断能力。

## 2. 清理记录

- 删除文件：无。理由：没有确认无用且可安全删除的项目文件。
- 删除依赖：无。静态引用不能充分证明所有 XAML/反射/运行期依赖无用，故未凭包名删依赖。
- 保留：用户既有 `desc.txt`、`publish/`、`obj/`、安装器资源、应用图标、许可证、发行说明以及全部 Git 元数据。
- 清理前后文件数：开始扫描时目录递归计数为 1,861（包含 Git/构建/发布内容）；本次新增本报告与源码/测试修改，没有做文件清理，因此不将总数下降宣称为成果。已跟踪文件基数为 110。

## 3. GitHub 竞品研究

研究目标聚焦 Windows 端系统清理、维护和安全工具。仅借鉴产品流程/架构思路，没有复制代码、资源或依赖。

| 仓库 | 项目定位与许可证 | 可核对的规模/活跃度 | 可借鉴设计 | 与本项目差距 |
|---|---|---|---|---|
| https://github.com/bleachbit/bleachbit | 跨平台系统清理器，GPL-3.0 | GitHub 页面于 2026-11-06 抓取时约 7.4k stars；以仓库页面/发行记录为准 | 对清理对象与释放空间的明示、按需选择、清理前预览 | 本项目包含安全中心、Defender 扫描、隔离等更广能力；清理产品化流程仍可继续增强 |
| https://github.com/Sophia-Community/SophiApp | Windows 配置管理工具，MIT | GitHub 页面显示约 5.2k stars；最近可核对更新为 2026-09-11 | 分类清晰的设置项、每项变更说明、恢复默认/可逆设置 | 本项目更偏安全监测，不能照搬大量隐私/系统策略开关；设置审计与撤销说明可以加强 |
| https://github.com/laurentiu021/SystemManager | Windows 系统信息与维护工具 | Star 数和许可证本次未可靠核验；引入代码前需检查仓库当前 LICENSE | 将系统工具按任务聚合、保持原生 Windows 工作流 | 本项目已有对应高级工具/维护模块，适宜借鉴信息组织而不是再造同类功能 |

Star 数是本次 2026-11-09 研究时的页面近似值，会变化，不代表质量排名。许可证名称以各仓库当前 LICENSE 文件为准；本次没有复用其源代码，因此没有许可证迁移。

## 4. 发现的问题

### 已修复

1. **扫描取消等待 Defender 停止命令，且该命令按进程名结束 MpCmdRun。** 原实现存在长时间等待，并可能影响其他程序启动的 MpCmdRun。本次改为取消本扫描自己的令牌，让本次扫描子进程按其取消令牌退出；同时移除确认没有调用点的危险停止接口和实现。
2. **扫描开始状态检查与 CTS 初始化不原子。** 两个并发调用可能同时通过状态判断。本次在同一锁中初始化运行状态与 CTS，并在结束时仅清理对应运行 CTS。
3. **SmartRisk 上下文使用原始请求范围而不是规范化后的实际扫描范围。** 快速/全盘扫描上下文现在与实际根路径一致。
4. **临时估算取消令牌未释放，估算任务可能拖延扫描收尾。** 使用有作用域的 2 分钟取消源，并在主扫描结束后取消估算任务。
5. **PowerShell 进程异步输出读取可能在退出后尚未排空。** 等待进程退出后显式等待输出事件读取完成，再取 stdout/stderr。
6. **取消测试原本先 await 扫描完整结束，导致取消语句无法在扫描运行时执行。** 改成保留扫描任务并发起取消后等待结束。
7. **维护清理目标从可编辑描述中提取，且执行时没有复查文件年龄。** 改为仅允许服务内固定 ID 映射到预定目录，并在删除时重验年龄；未知 ID/伪造路径不触发删除。新增回归测试覆盖伪造目录参数。

### 仍需跟进

- 构建报告 `NU1701`：`OpenTK 3.3.1`、`OpenTK.GLWpfControl 3.3.0`、`SkiaSharp.Views.WPF 3.116.1` 使用 .NET Framework 资产回退到 `net10.0-windows`。构建成功不等于依赖完全兼容；应评估 LiveCharts/SkiaSharp 对应的新资产或升级路径，并进行真实图表渲染回归。
- WinForms/WPF 混用的 `WFO0003`：manifest 中 DPI 配置与当前 WinForms 高 DPI 建议冲突。需结合 Windows 多屏、高缩放、拖动窗口实测后处理。
- `ConfigService.SaveAsync` 捕获所有异常后只写日志；调用方无法获知持久化失败。需设计兼容的错误回传并验证设置保存失败 UI。
- `AppDatabase` 的版本 1 初始化目前创建 schema 后标版本；未来迁移需补充版本分支与旧库升级测试。
- 自动更新包含下载安装并静默运行安装程序的能力。尚未对真实 Release 资产、签名/撤销链和安装/回滚做端到端验证；当前任务没有触发更新，也没有安装或上传构建产物。
- 部分平台查询使用宽泛 `catch` 并返回空列表/默认值，错误可观测性不一致；后续应区分“不支持、权限不足、查询失败”。
- 界面逐页的实际交互、缩放/主题/空状态未做人工 UI 验收；代码构建和测试不能替代交互验收。

## 5. 功能差距与升级建议

| 类别 | 项目/问题 | 建议、涉及模块 | 验收标准与风险 |
|---|---|---|---|
| A 必修 | PowerShell/Defender 错误与取消的可观测性 | Platform PowerShell/Defender、Core 扫描状态 | 模拟超时、取消、非零退出均能及时完成并显示可解释错误；避免影响其他进程 |
| A 必修 | 图表包兼容告警 | App 项目包版本、图表控件 | 去除 NU1701 后 Release 构建通过，CPU/内存/网络曲线在 Win10/11、不同 DPI 下正常 |
| B 核心补齐 | 安全扫描报告持久化覆盖与失败状态核验 | ScanOrchestrator、仓储、UI | 完成、取消、失败均可查询；威胁计数无历史串入 |
| C 实用新增 | 清理前预览/分类/选择、清理后明细 | Maintenance 服务与页面 | 对每项显示路径、类型、大小、原因；测试目录可回归；危险目录始终拒绝 |
| D 现有升级 | 配置保存错误反馈；权限不足与错误状态细分 | ConfigService、设置 ViewModel、Platform 查询 | 故意不可写配置目录时 UI 告知失败且旧文件不损坏 |
| E 外部设计借鉴 | 清理预览与可逆设置说明 | 仅借鉴 BleachBit/SophiApp 用户流程 | 不复制代码，不引入新依赖；危险操作需可解释和可回退 |
| F 冗余删除 | 暂无能确认无用的文件/包 | 继续等待运行期与 XAML 引用证据 | 在没有完整引用证据前不删除 |
| G 暂缓 | 自动修改隐私、服务、网络防火墙规则或“智能自动修复” | 暂不整合第三方实现 | 误改系统配置的影响大，且超出当前本地审计的安全验收边界 |

## 6. 架构与 UI/UX 评估

当前 Core/Platform/Data/App 分层有清晰方向，UI 使用 WPF + ViewModel，平台专属调用集中在 Platform。此次未作大规模重构，因为静态审计与自动化测试不足以证明整体页面/系统维护功能的交互安全性。架构小修限于扫描状态生命周期、取消传播与输出读取，不改持久化结构或公开业务接口。

UI 有暗/亮主题资源和 13 个页面，功能覆盖面较广。此次没有重绘页面或改主题：未在这次任务中启动应用做屏幕级人工验收。建议下一阶段围绕“扫描/威胁处理、维护清理、更新中心”三个高影响流程做可访问性、DPI、空/错误/加载状态与键盘操作实测。

## 7. 测试报告

使用项目旁已有的 .NET 10.0.100 SDK（路径 `C:\Users\lenmo\dotnet-setup\sdk10`），未安装新依赖或改全局环境。

- `dotnet build PcSecurityCenter.slnx -c Release --no-restore --nologo`：通过，0 错误；有 8 条警告（NU1701 和 WFO0003）。首次构建还原依赖时另有相同 NU1701 告警。
- 全量 `dotnet test tests/PcSecurityCenter.Tests/PcSecurityCenter.Tests.csproj -c Release --no-build --nologo`：82/82 通过，0 失败、0 跳过，用时约 1 分 17 秒。
- 扫描取消回归：通过；自定义目录检出回归：通过。
- `dotnet list PcSecurityCenter.slnx package --vulnerable --include-transitive`：当前 NuGet 源没有报告易受攻击包。此结果受源数据库与检查日期限制，不能当作永久安全证明。
- UI 端到端操作、安装包构建、自动更新真实下载/安装、Windows 10 兼容性、本次发布流程未运行。
- 本次没有启动本地 Web 服务或占用网络监听端口。全量扫描测试运行了 Defender 快速扫描；任务未停止其他进程。

## 8. 文件修改记录

新增：

- `PROJECT_AUDIT_REPORT.md`：本审计报告。

修改：

- `src/PcSecurityCenter.Core/Scanning/ScanOrchestrator.cs`：扫描状态并发保护、规范化范围上下文、估算任务取消/释放、仅取消当前扫描。
- `src/PcSecurityCenter.Core/Abstractions/IScanAbstractions.cs` 与 `src/PcSecurityCenter.Platform/Defender/DefenderClient.cs`：移除无调用且按进程名强杀 MpCmdRun 的停止接口。
- `src/PcSecurityCenter.Platform/PowerShell/PowerShellRunner.cs`：确保退出前异步输出读取已完成。
- `src/PcSecurityCenter.Platform/Maintenance/WindowsMaintenanceService.cs`：固定清理目标白名单并执行年龄复核。
- `tests/PcSecurityCenter.Tests/ScanCommandTests.cs`：修复取消测试等待顺序。
- `tests/PcSecurityCenter.Tests/IntegrationTests.cs`：新增伪造维护清理目录的安全回归测试。

删除/移动：无。用户既有 `desc.txt` 保留。

## 9. 最终质量评估

本地质量从“构建与测试基线可用，但扫描取消存在长等待/跨进程风险，且扫描状态初始化有竞争窗口”提升为“修复上述扫描生命周期风险，Release 构建通过，81 项测试通过”。没有做未经充分验证的大功能迁移、依赖移除或危险清理。

当前可交付状态：代码/测试修复可供验收；项目整体不能据此宣称已完成全部深度重构或生产发布验收。主要残余风险是图表依赖兼容告警、DPI 行为、配置保存错误反馈、更新安装链和人工 UI 验收。

## 10. 后续建议与验收重点

1. 验收快速/自定义扫描的取消状态、进度归零及扫描结束后再次启动行为。
2. 在非管理员与管理员环境分别检查 Defender、隔离恢复、维护提权；确认拒绝授权时不产生副作用。
3. 使用真实 Windows 10/11、多显示缩放屏幕验证图表、托盘和 DPI。
4. 单独建立签名测试 Release 资产，验证更新 SHA256、签名吊销检查、安装失败恢复；不要用生产发布直接试验。
5. 解决 NU1701/WFO0003 后再做 Release 和 UI 回归。
6. 确认满意后再由用户决定是否提交或推送；本任务没有提交、推送、创建远程标签、发布 Release 或上传文件。


