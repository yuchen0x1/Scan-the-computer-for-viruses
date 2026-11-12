# 全面审计与升级方案（v1.1.0 → v1.2.0）

审计日期：2026-11-10
审计对象：`C:\Users\lenmo\Desktop\Scan the computer for viruses\PcSecurityCenter`
基线版本：1.1.0（`Directory.Build.props` 为版本单源）
审计方式：源码静态审计 + 本机实测复现 + 真实运行数据核对（未做任何推断性结论）

> **实施状态更新（2026-11-10）**：P0 提权、扫描分区、ThreatID 定点处理、RunId 贯穿已在当前工作区实现；并追加修复隐藏属性下旧 `vault.key` 无法原地覆盖的迁移缺陷，以及扫描分区根目录直系文件漏扫、历史 Defender 记录错归属问题。旧版本结果与实现前数据仍作为审计证据保留；最终构建/全量测试/UI 验证结果见本文末尾实施记录。

---

## 一、结论摘要

| 维度 | 现状 | 判断 |
|---|---|---|
| Release 构建 | 0 错误 / **11 警告**（9× NU1701 + 2× WFO0003） | 可构建，但依赖兼容性未诚实收敛 |
| 自动化测试 | **82/82 通过**（1m07s） | 基线可信 |
| 安全边界设计 | 提权白名单、隔离区 AEAD、更新链校验、路径安全 | 设计方向正确，工程质量高于同类开源项目 |
| 安全边界**实现** | 提权实际从未生效（P0-1） | **设计与实现脱节，必须修复** |
| 检测质量 | 单次扫描 3,970 条告警，**其中 3,969 条（99.97%）来自同一条规则** | 告警信噪比不可用，实质等于没有告警 |
| 数据完整性 | `threats.scan_run_id` 与 `scan_runs.id` **0 条能关联** | 报告中心的"按扫描归档"未成立 |

**总评**：这是一个架构分层清晰、安全意图明确、文档诚实度高的项目；问题不在设计而在**若干关键实现细节**，其中 4 项属于"对外承诺的行为与实际行为不一致"，属于必须优先修复的正确性缺陷。

**建议**：不做大重构。按 P0 → P1 → P2 三批推进，**1.2.0 只修正确性，1.2.1 修告警质量与体验，1.3.0 做工程化**。预计 P0 批约 1.5 人日、P1 批约 2.5 人日。

---

## 二、实测复现记录

本节所有结论均在本机可复现，不是静态推测。

### 2.1 基线构建与测试

```
dotnet build PcSecurityCenter.slnx -c Release --nologo
  → 已成功生成, 11 个警告, 0 个错误
dotnet test ...PcSecurityCenter.Tests.csproj -c Release --no-build
  → 已通过! 失败: 0, 通过: 82, 已跳过: 0, 总 1m07s
```

### 2.2 提权链路实测（P0-1 证据）

`WindowsPermissionService.cs:44-47` 构造：`UseShellExecute = false` + `Verb = "RunAs"` + 重定向 stdout。

用等价的最小复现程序验证（父进程非管理员）：

```
parent elevated = False
child output: False | stderr:  | exit=0
```

子进程 `IsInRole(Administrator)` 返回 **False**，且**全程没有弹出 UAC**。结论：`Verb=RunAs` 在 `UseShellExecute=false` 下被静默忽略，所谓的"提权执行"只是以普通权限跑了一遍脚本。SFC / DISM / chkdsk / 还原点 / 计划任务启停 / 服务启停全部走这条路径。

### 2.3 全盘扫描目录分区实测（P0-2 证据）

`ScanOrchestrator.cs:284-289` 的嵌套 `EnumerateDirectoriesShallow`，在 21 个文件的构造目录树上实测：

```
actual files in tree: 21
directories handed to Defender: 9
total file-inspections = 69  (duplication x3.29)
distinct dirs emitted: 7
```

原因：内层 `EnumerateDirectoriesShallow(dir)` 又一次 yield 自身与子目录，导致**祖先目录与后代目录同时被投递**，Defender 对同一子树反复递归扫描。目录越深，重复倍数越高。

### 2.4 告警构成实测（P1-1 证据）

读取本机 `%APPDATA%\PcSecurityCenter\security.db`（只读）：

```
scan_runs: 1 条，files_scanned=153558，threats_found=3970
threats 引擎/结论分布:
  ('MicrosoftDefender', Confirmed, Active, 8)
  ('SmartRisk', Suspicious, Active, 3969)
  ('SmartRisk', Notice,     Active, 1)

规则命中分布:
   3969  临时/下载目录中的可执行脚本
      1  启动目录中的脚本文件

扩展名分布: .js 3920, .ps1 36, .cmd 13, .bat 1
其中位于 node_modules: 1457
```

即 99.97% 的告警是**同一条规则**在 `%TEMP%` 下把所有 `.js` 一律标为 Suspicious。这不是检测能力，而是告警噪音。

### 2.5 数据关联实测（P0-4 证据）

```
threats 总数: 3978
能 join 到 scan_runs 的: 0
威胁里出现的 scan_run_id: 3efe41de-… （该 id 在 scan_runs 中不存在）
```

`ScanOrchestrator.contextFor()` 每次都 `Guid.NewGuid()`，`ScanViewModel` 又另建一个 `ScanRunRecord` 的 Guid，两者永不相等。

### 2.6 发布脚本实测（P2-1 证据）

```
pwsh 7.6.9      → PARSE_OK
PowerShell 5.1  → PARSE_ERRORS=1  字符串缺少终止符: "。 @line 62
```

根因：`publish.ps1` 是 **UTF-8 无 BOM**，PS 5.1 按 ANSI 读取，第 62 行中文句号 `。` 的字节序列破坏了引号配对。这与历史记录一致，且至今未修。

### 2.7 NU1701 / WFO0003 修复验证（已实做）

已在工作区实做并验证通过（详见 §4.1），结论：

- App 目标框架 `net10.0-windows` → `net10.0-windows10.0.19041.0`，LiveCharts `2.0.0-rc5.4` → `2.0.5`
- 结果：**0 警告 0 错误**，82/82 测试通过
- 图表实测：性能监控页 CPU 曲线真实波动、悬停提示 `CPU % 52.819809`，说明 SkiaSharp 3.119 渲染链路正常
- 反向验证：改用 `net10.0-windows10.0.17763.0` **仍然报 NU1701**（SkiaSharp 只有 `net6.0-windows10.0.19041` 资产组）

---

## 三、缺陷清单

### P0 — 必须修复（对外承诺 ≠ 实际行为）

#### P0-1 提权执行从未生效，且 UI 明确告知用户"将以管理员权限执行（UAC 确认）"

- **位置**：`src/PcSecurityCenter.Platform/Security/WindowsPermissionService.cs:31-76`
- **证据**：§2.2
- **影响**：所有需要管理员的系统维护功能（SFC、DISM、chkdsk、创建还原点、计划任务启停、服务启停）在标准权限下必然失败，且失败原因被包装成"操作失败：<脚本输出>"，用户无法得知**根本没有提权**。这是"安全工具告诉用户已做安全操作、其实没做"的典型信任破坏。
- **附带缺陷**：方法签名接收 `CancellationToken` 但从未使用；UAC 被用户取消时（Win32 `ERROR_CANCELLED=1223`）没有专门识别与提示。

#### P0-2 全盘扫描重复扫描子树

- **位置**：`src/PcSecurityCenter.Core/Scanning/ScanOrchestrator.cs:278-300`
- **证据**：§2.3（3.29× 冗余）
- **影响**：全盘扫描耗时成倍放大；`FilesScanned` 统计虚高（同一文件被计数多次），进度百分比失真；Defender 反复扫描同一路径也放大了 IO 与 CPU 占用。真实磁盘目录层级远深于测试树，实际倍数会更高。

#### P0-3 单个威胁"隔离"会清除 Defender 的全部威胁记录

- **位置**：`DefenderClient.cs:170-175` + `ScanViewModel.cs:288-300`
- **证据**：`Remove-MpThreat` 脚本不带任何 `-ThreatID` 参数；接口 `RemoveThreatsAsync(CancellationToken)` 也不接收 id
- **影响**：用户在威胁列表点某一条 Defender 威胁 → 执行的是"清除所有活动威胁"。这是**范围过大的破坏性操作**，与二次确认框里"将通过官方接口清除该威胁"的表述不符；且 `RemoveThreatsAsync` 不校验传入路径是否属于该威胁，任何一条记录都能触发全局清除。

#### P0-4 威胁与扫描任务无法关联，报告中心"按扫描归档"不成立

- **位置**：`ScanOrchestrator.cs:178-183`、`ScanViewModel.cs:235-247`、`ScanOrchestrator.CollectDefenderDetectionsAsync`
- **证据**：§2.5，3978 条威胁 0 条可关联
- **影响**：无法回答"这次扫描发现了什么"；`threats.scan_run_id` 形同虚设；取消/失败/完成的扫描之间威胁串档的风险无法排除；`ScanRunRecord.ThreatsFound` 与列表内容无法交叉校验。

### P1 — 高优先级（可用性与信任）

#### P1-1 SmartRisk 单条规则制造 99.97% 噪音

- **位置**：`SmartRiskEngine.cs:88-96`（规则 3）
- **证据**：§2.4
- **细节**：规则把 `%TEMP%`/Downloads 下**任意** `.scr` 或脚本扩展名判为 `Suspicious/Medium`，`ScriptExt` 里 `.js` 与 `.ps1` 同权；不区分 `node_modules`、`.tmp*` 解包目录、VS 构建临时目录；不做目录级聚合。
- **影响**：3,970 条结果里真正需要人看一眼的可能是个位数。用户第一次扫描就会学会"全部忽略"，规则的防护价值归零——这比没有该规则更糟。同时 `ScanViewModel.Threats` 用 ObservableCollection 承载数千条，会造成明显 UI 卡顿。

#### P1-2 实时防护进程集合被 `.Clear()`，引发周期性误报风暴

- **位置**：`WindowsRealtimeProtector.cs:236-239`
- **影响**：`_knownProcessIds` 超过 2000 时整体清空 → 清空后**所有正在运行的进程都被当作"新进程"**，凡是位于临时目录的就各发一条 Medium 事件。本机实测截图已出现连续多条 `vctip` / `cl` / `mspdbsrv` 的"临时目录中的新进程"（均为 Visual Studio 正常构建工具）。与 P1-1 同属噪音家族。

#### P1-3 实时防护页状态自相矛盾

- **位置**：`ProtectionNetworkSecurityVMs.cs:39,63-66`；页面卡片
- **证据**：截图同时显示"实时防护：运行中"与"实时防护 关闭；行为监控 关闭"，标题栏另显示"防护状态异常"
- **影响**：前两处含义不同（前者=本应用守护进程，后者=Defender 的 RTP）但都叫"实时防护"，用户无法分辨，且与标题栏的红点结论互相打架。

#### P1-4 自动更新可在扫描进行中静默重启应用

- **位置**：`MainWindow.xaml.cs:129-141,192-209`；`UpdaterService.ApplyAndRestart`
- **影响**：60 秒倒计时到点直接 `ApplyAndRestart()` 并 `Environment.Exit(0)`，完全不检查 `ScanState`。全盘扫描中途被杀，用户既没扫描结果也没提示。另外每次启动都无条件 `CheckAsync()` + `DownloadAsync()`（约 90–94 MB），无用户同意、无网络类型判断。

#### P1-5 GitHub API 匿名限流导致更新检查必然间歇性失败

- **位置**：`UpdaterService.cs:32-33, 89`
- **证据**：本机启动日志实测 `403 (rate limit exceeded)`
- **影响**：每次启动调 2 次 API（`CheckAsync` + `UpdateViewModel.LoadChangelogAsync`），同一出口 IP 下极易触顶。无 ETag 缓存、无退避、无本地上次结果回退。

#### P1-6 设置页存在多个"假开关"

| 设置项 | 引用数（除定义/赋值外） | 实际行为 |
|---|---|---|
| `HashLookupEnabled` / `HashLookupApiKey` | 0 | 无任何实现，UI 承诺联网查询却不存在 |
| `AutoUpdateDefenderSignatures` | 0 | 从不执行，勾选无效 |
| `ScanExclusions` | 0 | 不排除任何路径（也让 P1-1 无法靠排除缓解） |
| `MaxLogDays` | 0 | 日志保留实际由 `LoggingSetup` 硬编码 30 天 |
| `FirstRunCompleted` | 0 | 无首次运行流程 |

- **影响**：`ConfigService.SaveAsync` 吞掉所有异常且 UI 无条件提示"设置已保存"（`FileAnalysisReportSettingsVMs.cs:314-321`），用户无法区分"保存成功""保存失败""保存了但没实现"。

#### P1-7 "关于"对话框版本号硬编码 v1.0.0

- **位置**：`FileAnalysisReportSettingsVMs.cs:339`
- **影响**：当前 1.1.0，标题栏显示 v1.1.0，关于框显示 v1.0.0；版本号"单源化"只覆盖了构建产物，未覆盖用户可见文案。

### P2 — 工程质量

| # | 问题 | 位置 | 说明 |
|---|---|---|---|
| P2-1 | `publish.ps1` 在 PS 5.1 下无法解析 | `publish.ps1:62` | UTF-8 无 BOM；§2.6 实测 |
| P2-2 | NU1701 依赖回退 | `App.csproj` | **已修复并验证**，见 §4.1 |
| P2-3 | WFO0003 与 WPF DPI 冲突 | `app.manifest` | WinForms 建议删 manifest DPI，但 WPF 的 PerMonitorV2 只能靠 manifest；应带注释抑制而非删配置 |
| P2-4 | 死依赖 | 3 处 | `Microsoft.Extensions.Hosting`(0 引用)、`Serilog.Sinks.Console`(0)、Core 里的 `CommunityToolkit.Mvvm`(0) |
| P2-5 | 全盘进度总量跳动 | `ScanOrchestrator.cs:311-313` | `Math.Min(estimate, FilesScanned+5000)` 使百分比反复回退 |
| P2-6 | 无辅助功能标注 | 全部 XAML | `AutomationProperties` 引用数为 **0**，导航项与图标按钮无可用名称 |
| P2-7 | `IsAvailable` 同步阻塞属性 | `DefenderClient.cs:30-35` | `GetAwaiter().GetResult()`，误用即死锁 |
| P2-8 | 全盘流式扫描的无效同步 | `ScanOrchestrator.cs:291-297` | 单写者场景下 `_pauseGate`(1,1) 无意义；`SingleReader=false` 应为 true；`batchStart` 赋值后未使用 |

---

## 四、升级方案

版本策略：**1.2.0（正确性）→ 1.2.1（告警质量与体验）→ 1.3.0（工程化）**。每批次独立可发布、独立可回滚。

### 4.1 已实做的改动（工作区当前状态）

| 文件/范围 | 改动 | 验证结果 |
|---|---|---|
| `src/PcSecurityCenter.App/PcSecurityCenter.App.csproj` | `net10.0-windows` → `net10.0-windows10.0.19041.0`；LiveCharts `2.0.0-rc5.4` → `2.0.5`；`NoWarn` 抑制 WFO0003 并注明原因 | 前序构建 **0 警告 0 错误**；性能页图表渲染正常；本轮全量验证待完成 |
| 提权及维护调用 | 新增 `ElevationLauncher`；使用 ShellExecute/RunAs、编码脚本及临时 JSON 回传；取消/超时可见；维护操作传递取消令牌 | 前序实测子进程管理员 token 为 True；当前回归 19 项已含提权断言 |
| 扫描分区/编排 | 使用直接子目录反链；补入与子目录并存的根级普通文件；Defender 文件单元计 1；RunId 同一扫描贯穿 | 当前需运行新增混合根覆盖测试及全量测试；此前分区避免嵌套重复已在真实 C: 测量 |
| Defender 威胁处理 | 由不限定范围改为 `Remove-MpThreat -ThreatID` 并拒绝非法 ID | 当前回归覆盖非法 ID；未对真实威胁执行清除 |
| 隔离密钥迁移 | 对隐藏的 v1 明文 key 使用同目录临时文件 + `File.Replace`；DPAPI 往返验证后才删备份，失败回滚；保留既有 key/隔离内容 | 本机复现 `Hidden + WriteAllBytes` 拒绝、移除 Hidden 后成功；隐藏 key 迁移与恢复专项 **4/4 通过** |
| Defender 历史记录归属 | 编排器及 UI 仅将时间窗口内检测归属当前扫描，避免最近 30 天历史记录被改写 RunId | 代码已收紧；尚待全量测试/页面验收 |
| 回归测试 | `P0RegressionTests.cs` 覆盖提权、分区、RunId、ThreatID；集成测试覆盖隐藏 key 与旧隔离格式恢复 | 既有新增测试前序结果 19/19；当前隔离专项 4/4；全量重跑待完成 |

**取舍必须写进发布说明**：目标框架带最低 OS 版本后，安装包实际要求 **Windows 10 2004 (19041) 及以上**（原 README 写"Windows 10/11 x64"过于宽泛）。若要支持 1809–1909，只能继续忍受 NU1701 或在图表层换库，不能靠改 TFM 绕过（§2.7 已验证 17763 无效）。

> 说明：工作区还有本次审计之前就存在的未提交改动（`Palette.Dark.xaml`、`Palette.Light.xaml`、`IScanAbstractions.cs`、`ScanOrchestrator.cs`、`DefenderClient.cs`、`WindowsMaintenanceService.cs`、`PowerShellRunner.cs` 及两个测试文件）。本方案未回退它们。

### 4.2 P0 批（1.2.0）—— 正确性

#### P0-1 提权链路重写

`UseShellExecute=false` 与 `Verb=RunAs` 互斥，且 `UseShellExecute=true` 下**不允许** `RedirectStandardOutput` 或 `EnvironmentVariables`（实测抛出 `InvalidOperationException: The Process object must have the UseShellExecute property set to false in order to use environment variables.`）。

因此改为"**提权子进程写结果文件**"模式：

```
父进程
  ├─ 把 op 与参数序列化进 -EncodedCommand（base64，无拼接，天然防注入）
  ├─ 结果路径 = %TEMP%\psc_elev_<guid>.json（脚本内嵌）
  ├─ psi.UseShellExecute = true; psi.Verb = "RunAs"; 不重定向
  ├─ 捕获 Win32Exception 1223 → 明确返回"用户取消了 UAC 提权"
  ├─ WaitForExit(超时) → 读结果文件 → 删除
  └─ 结果文件缺失 → 返回"提权进程未返回结果"，绝不当作成功
```

实现状态：已抽出 `ElevationLauncher.CreateStartInfo`；使用 `UseShellExecute=true`、`Verb=RunAs`、关闭输出重定向；取消令牌接入等待轮询；Win32 1223 单独提示；子进程必须确认管理员 token 并写回 JSON 结果，否则按失败处理。相关配置、参数转义、失败路径均有回归测试，生产启动方式已在本机验证子进程管理员 token 为 True。

**验收**：非管理员账户点"SFC 扫描" → 必须弹 UAC；取消后 UI 显示"已取消提权"，且不产生任何副作用；确认后 `sfc /verifyonly` 输出出现在结果里。

#### P0-2 全盘扫描分区改为"反链"（antichain）分区

不变量：**投递给 Defender 的目录集合任意两个元素之间不存在祖先/后代关系；目录单元与根目录直系文件合计覆盖根路径且恰好一次**。

实现采用 root 的直接子目录作为目录单元；root 存在子目录时，再把其直接普通文件作为独立文件单元（PowerShell 扫描后按 1 个文件计数）；没有有效子目录则保留 root 单元。这样兼顾反链、不漏根级文件、进度粒度约每盘十几个到几十个目录单元。清理了无效 `_pauseGate` 生产端等待并设置 `SingleReader=true`。

**验收状态**：已有反链/覆盖测试；本次新增混合根（根级文件 + 子目录）断言，检查逐文件集合完全相等、无重复及反链。此前真实 C: 分区实测 24 个单元、5ms，旧方案 259 个路径 / 235 个唯一项；尚未执行实际 Defender 全盘扫描（避免长时间占用机器）。

#### P0-3 威胁清除改为按 ID 定点

- 接口改为 `Task<bool> RemoveThreatAsync(long threatId, CancellationToken ct = default)`
- 脚本：`Remove-MpThreat -ThreatID $env:PSC_TID`，`$env:PSC_TID` 必须是纯数字（`[int64]::TryParse` 校验，失败直接拒绝，不进脚本）
- `ScanViewModel` 传入 `t.DefenderThreatId`；为空时拒绝执行并提示"该记录无 Defender 威胁 ID，请到 Windows 安全中心处理"
- 若确需"清除全部"，单独加显式命令与更强的确认文案

**验收**：单测断言脚本含 `-ThreatID` 且注入非数字被拒；真机存在 ≥2 条 Defender 记录时，只处理点击的那一条。

#### P0-4 扫描运行 ID 贯穿全链路

实现状态：`ScanOrchestrator.StartAsync` 为每次扫描创建唯一 `runId`，经 `ScanProgress`、`ScanContext`、ThreatInfo 与 ScanRunRecord 贯穿；Defender 历史记录按开始时间窗口过滤，UI 完成回调只补充本次时间窗口内记录。历史 DB 中既有悬空 `scan_run_id` 尚未迁移清理，需作为独立兼容/数据修复任务评估，避免直接更改用户历史审计数据。

**验收**：跑一次快速扫描后执行
`select count(*) from threats t join scan_runs s on t.scan_run_id=s.id` 必须 > 0，且等于该次扫描告警数。

### 4.3 P1 批（1.2.1）—— 告警质量与体验

#### P1-1 SmartRisk 规则分级 + 路径白名单 + 目录聚合

按"扩展名危险度 × 路径上下文 × 内容证据"三维打分，取代现在的一刀切：

| 场景 | 结论 |
|---|---|
| `.scr`/`.hta`/`.vbs`/`.wsf`/`.jse`/`.vbe` 位于 Temp/Downloads | Suspicious / Medium（保留） |
| `.ps1`/`.bat`/`.cmd` 位于 Temp/Downloads，无内容命中 | Notice / Low（降级） |
| 同上但 `ScriptContentIndicators` 命中 | Suspicious / High（升级，保留现有证据链） |
| `.js` 位于 Temp/Downloads | 仅当**不**在 `node_modules`、`.git`、`dist`、`build`、`obj`、`bin`、带 `package.json` 的 `.tmp*` 解包目录下才报 Notice；否则跳过 |
| 同一目录命中 ≥3 个文件 | 聚合为 1 条"目录 X 下有 N 个可疑脚本"，明细折叠 |

同时让 `ScanExclusions` **真正生效**（配置→`ScanRangeBuilder`/`SmartRiskEngine` 双重过滤），并在设置页提供"添加排除路径"。

**验收**：在本机重跑快速扫描，SmartRisk 结果应从 3,970 降到**两位数**；每一条剩余结果都必须能单独解释"为什么它可疑"。这是本方案唯一可以直接用数字验收的产品指标。

#### P1-2 实时防护进程跟踪修正

- 用 `(pid, startTime)` 复合键，避免 PID 复用误判
- 只淘汰**已退出**的进程，禁止整体 `Clear()`
- 对已知构建工具链（`vctip`、`cl`、`link`、`msbuild`、`mspdbsrv`、`msiexec`）的临时目录进程降为 `Info` 或按目录聚合
- 事件按 `(path, 规则)` 做时间窗去重（启动目录已有 2s 去抖，进程侧缺失）

**验收**：连续构建一次 VS 项目，不产生 Medium 级"临时目录中的新进程"风暴。

#### P1-3 状态文案消歧

- 卡片标题明确区分：**"本应用防护：运行中/已停止"** 与 **"Defender 实时保护：开启/关闭"**
- 标题栏红点与页面首卡状态取同一数据源，禁止两处各自计算

#### P1-4 更新与扫描互斥

- `ApplyAndRestart` 前检查 `ScanState ∈ {Preparing, Running, Paused}` → 弹窗"扫描进行中，更新将中断扫描"，由用户决定
- 首次启动的自动下载改为：只 `CheckAsync`，下载需用户确认（或新增"自动下载更新"开关，默认关）
- 便携版/受限网络下允许"仅提醒不下载"

#### P1-5 更新检查加入条件请求与退避

- 持久化 `ETag` + `Last-Modified`，用 `If-None-Match` / `If-Modified-Since`，304 直接复用本地缓存
- 403/429 时按 `Retry-After` 或指数退避（1h → 6h → 24h），并把上次成功结果落盘，供"更新日志"离线回退
- 两处调用合并为一次（`CheckAsync` 的结果供 `LoadChangelogAsync` 复用）

#### P1-6 假开关处置（二选一，不许含糊）

| 项 | 决策 |
|---|---|
| `HashLookupEnabled`/`ApiKey` | **删除 UI**（无实现就不该出现）。若要保留，必须先实现并有明确的"仅发送哈希"提示 |
| `AutoUpdateDefenderSignatures` | **实现**（启动时若 >24h 未更新则触发一次 `Update-MpSignature`），或删除 |
| `ScanExclusions` | **实现**（P1-1 已包含） |
| `MaxLogDays` | 接进 `LoggingSetup` 的 `retainedFileCountLimit` |
| `FirstRunCompleted` | 实现首次运行引导，或删除 |

`ConfigService.SaveAsync` 改为返回 `bool`/抛异常，设置页据此显示"已保存"/"保存失败：<原因>"。

#### P1-7 版本号单源到 UI

`About`、`MainWindow.VersionText` 统一取 `Assembly.GetExecutingAssembly().GetName().Version`，禁止硬编码。

### 4.4 P2 批（1.3.0）—— 工程化

1. **`publish.ps1` 编码修复**：写入 UTF-8 BOM（`Set-Content -Encoding utf8BOM` 或 `[IO.File]::WriteAllText(..., New UTF8Encoding($true))`）；文件开头加版本守卫，检测到 PS 5.1 且存在 `pwsh` 时自我重启到 pwsh 7。
2. **WFO0003**：保留 manifest（WPF DPI 必需），用 `NoWarn` + 注释说明（已实做）。
3. **清理死依赖**：移除 `Microsoft.Extensions.Hosting`、`Serilog.Sinks.Console`、Core 的 `CommunityToolkit.Mvvm`（需先确认无 XAML/反射隐式引用，删后必须跑全量构建）。
4. **进度总量**：`FilesTotal` 只允许单调递增，估算完成前显示"正在统计…"而非跳变百分比。
5. **辅助功能**：为导航项、图标按钮、表格关键列补 `AutomationProperties.Name`；Tab 顺序与焦点可视化巡检。
6. **`DefenderClient.IsAvailable`**：改 `Task<bool> IsAvailableAsync()`，移除同步阻塞入口。
7. **CI 增强**：`dotnet build -warnaserror` 对 NU1701/WFO0003 生效；新增"扫描单元测试耗时"与"全盘分区不重复"专项。

---

## 五、实施顺序与工时

| 批次 | 内容 | 预估 | 交付物 |
|---|---|---|---|
| 1.2.0 | P0-1/2/3/4 + NU1701 与 WFO0003（已完成）+ 5 项新测试 | 1.5 人日 | 安装包 + 发布说明（含最低 OS 变更） |
| 1.2.1 | P1-1…P1-7 | 2.5 人日 | 安装包 + "告警数量前后对比"证据 |
| 1.3.0 | P2 全部 | 1.5 人日 | 可一键发布 + CI 全绿 |

依赖关系：P0-4 必须先于 P1-1 的验收（否则无法按扫描统计告警数量变化）；P0-3 独立可并行。

---

## 六、验收清单

**必须真机执行、必须留证据（截图/日志/SQL 结果）**

1. 非管理员运行：SFC / DISM / 还原点三项各点一次 → 必须出现 UAC；取消 → 显示"已取消提权"；确认 → 输出真实结果（提权链路已做独立本机 token 验证，完整 UI 操作仍待验）
2. 全盘扫描：`FilesScanned` ≤ 实际文件数（允许因权限跳过略少，**不允许超过**）；记录耗时（未执行真实全盘扫描）
3. Defender 存在 ≥2 条记录时，隔离其中一条 → 另一条仍存在（未对真实威胁执行处理）
4. 一次扫描后 SQL：`threats ⋈ scan_runs` 关联数 > 0 且等于本次告警数
5. 快速扫描 SmartRisk 结果 ≤ 100 条，且每条可解释
6. 连续构建一次 VS 项目 → 无 Medium 级临时目录进程告警风暴
7. 扫描中点"立即更新" → 出现"将中断扫描"确认；取消后扫描继续
8. `publish.ps1` 在 Windows PowerShell 5.1 与 pwsh 7 下均能完整跑通并产出 SHA256SUMS
9. 设置页每个开关：勾选 → 重启 → 行为可观察；保存失败路径（目录设为只读）必须提示失败
10. 性能页图表在 100%/125%/150% 缩放与暗色主题下均正常
11. 旧版隐藏 `vault.key` 迁移：在隔离测试目录运行迁移并恢复既有条目；不得清除或重置用户实际隔离库密钥

---

## 七、明确不做的事

- **不**为了消警告而删 DPI manifest（会让 WPF 失去 PerMonitorV2）
- **不**为了支持 1809 而降 TFM（已验证无效，且会牺牲图表渲染质量）
- **不**把 SmartRisk 升级为"病毒判定"引擎——现有"只提示、判定交给 Defender"的定位是正确的，本次只修噪音
- **不**新增第三方杀毒引擎或联网信誉查询（与"全本地、不上传"的产品承诺冲突）
- **不**引入自动修改隐私/服务/防火墙规则、自动"智能修复"（误改系统配置风险不可控）
- **不**在没有完整引用证据前删除源码文件或依赖

---

## 八、风险提示

1. **最低 OS 抬到 19041** 后，Windows 10 1809/1909 用户无法安装。发布说明与安装包 `MinVersion` 必须同步，否则会出现"装上了但起不来"。
2. **P0-3 行为变更**：接口签名改变，`IScanAbstractions` 的调用方需同步；这是破坏性变更，应在 1.2.0 一并说明。
3. **P1-1 规则放宽会降低召回**。必须保留"内容命中即升级为 High"的路径，并在发布说明中明确"减少的是噪音，不是检测面"。
4. **提权改造后无法再重定向输出**，所有诊断信息必须走结果文件；若结果文件写入被拒绝（TEMP 被 ACL 限制），必须给出明确错误而不是静默失败。
5. 现有 `security.db` 内 3,970 条历史规则命中建议**保留不删**（作历史证据），但 UI 默认只显示最近一次扫描的结果，并提供"归档清理"入口。

---

## 九、实施验证记录（2026-11-10）

- Release 全解决方案构建：**0 警告 / 0 错误**。
- 最新全量自动化测试：**101/101 通过，0 失败，0 跳过**（包含隐藏 key 迁移、旧隔离数据恢复）。
- 隐藏 key 根因复现：同目录副本具 `Hidden, Archive` 时 `File.WriteAllBytes` 抛 `UnauthorizedAccessException`；仅清除 Hidden 后覆盖成功，重新设 Hidden 又失败。当前实现用同目录临时文件 + `File.Replace`，避免直接 CREATE_ALWAYS 覆盖隐藏目标。
- UI 验证：新构建启动后「病毒查杀」页成功呈现，隔离库、威胁列表与 Defender 状态加载完成；首次进入时通过同一迁移实现将用户原 32 字节隐藏 key 转为 316 字节 DPAPI 密钥。独立人工备份已清理；隔离目录只剩 DPAPI key（Hidden），没有旧 key/临时文件残留。既有隔离文件若存在，仍使用相同原始 AES key，4/4 专项测试验证了旧格式隔离数据可恢复。
- 本次未执行真实全盘扫描、真实威胁清除、安装包发布或上传；`publish.ps1` 的 PowerShell 5.1 编码问题仍未修复。

---

## 十、附：本次审计未覆盖的范围

- 安装包 UI 全流程（Inno 向导各页面）未重跑
- 自动更新真实下载/安装/回滚端到端未执行（未触发更新，未上传任何产物）
- Windows 10 真机兼容性未验证（本机为 Windows 11 Insider Preview 29704）
- 暗色主题逐页视觉验收仅抽样
- 未做任何提交、打标签、推送或发布操作
# 2026-11-12 执行结果补充

本次已落地：扫描排除路径、SmartRisk 低信号降级、实时进程 PID+启动时间基线、进程事件去抖、更新下载/重启用户确认、配置保存失败反馈、日志保留天数、Defender 病毒库自动更新，以及移除未实现的哈希信誉设置入口。Release 构建 0 警告/0 错误，完整测试 104/104 通过。真实全盘扫描、威胁处理、安装包和 UI 人工验收仍待受控 Windows 测试机执行。

