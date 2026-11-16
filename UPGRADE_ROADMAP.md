# UPGRADE_ROADMAP.md

> 版本：2026-11-16
> 目标：把审计和竞品研究转成可实施、可验收的升级项。
> 状态含义：已实施 = 本轮有代码或配置证据；部分 = 已有基础但验收链未闭环；计划 = 尚未改代码；阻塞 = 需要外部凭据、签名材料或受控机器。

以下每一行固定包含 12 个字段：编号、升级名称、所属模块、当前问题与依据、竞品参考、改进方案、预期效果、文件/模块、难度、优先级、验收标准、状态。

## P0：安全与发布正确性

| 编号 | 升级名称 | 所属模块 | 当前问题与依据 | 竞品参考 | 改进方案 | 预期效果 | 文件/模块 | 难度 | 优先级 | 验收标准 | 状态 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| EV-001 | 更新包校验后防替换 | 更新中心 | 校验和启动之间原先关闭句柄，临时目录可被替换 | Velopack、NetSparkle 的签名/安装边界 | 受保护目录、拒绝重解析点、随机 part、持有禁止写删句柄、启动前重校验 | 关闭主要 TOCTOU 路径 | src/PcSecurityCenter.App/Services/UpdaterService.cs | 中 | P0 | 篡改下载文件、重解析点或移出目录时应用更新拒绝；正常包可启动安装器 | 已实施 |
| EV-002 | 发布版本元数据一致性 | 发布工程 | Directory.Build.props、Inno fallback、README 曾出现 1.2.5/1.2.6 漂移 | ClamWin/Portmaster 的 release 资产命名 | 新增版本校验脚本并接入 CI，统一当前示例为 1.2.7 | 手工打包和 Release 不再错标版本 | tools/Validate-ReleaseMetadata.ps1、README.md、installer/PcSecurityCenter.iss、.github/workflows/ci.yml | 低 | P0 | 脚本报告 8 项通过；故意改旧版本时 CI 失败 | 已实施 |
| EV-003 | 清理重复 DI 注册 | 应用启动 | App.xaml.cs 重复注册 WindowsTasksAndServices | Wazuh/Portmaster 的单一服务图 | 删除重复注册，保留一个 singleton | 降低容器配置歧义 | src/PcSecurityCenter.App/App.xaml.cs | 低 | P0 | 构建通过，服务解析仍为同一实例 | 已实施 |
| EV-004 | 发布清单签名与内置公钥 | 更新中心/供应链 | SHA256SUMS 与安装包同源，仓库被攻破时可同步替换 | NetSparkle、现代更新器签名 appcast | 用离线私钥签 manifest，客户端内置公钥并支持轮换 | 提供发布者认证而非只有完整性校验 | UpdaterService、release.yml、tools/sign-manifest.ps1 | 高 | P0 | 篡改 manifest、资产或签名均拒绝；密钥轮换有兼容测试 | 计划 |
| EV-005 | 受限提权结果通道 | UAC/维护 | 提权结果写入 %TEMP% 随机 JSON，仍受目录 ACL 影响 | Windows 安全工具的受保护 IPC | 使用用户数据目录 ACL、CreateNew，或继承句柄/匿名管道 | 降低管理员进程写任意文件风险 | src/PcSecurityCenter.Platform/Security/WindowsPermissionService.cs | 中 | P0 | 预创建结果路径、替换为重解析点时操作失败且不覆盖外部文件 | 已实施 |
| EV-006 | 隔离恢复重解析点防护 | 隔离库 | 目标目录可被重解析点改变；存在检查与移动之间边界 | ClamWin/端点隔离的恢复保护 | 校验目标目录所有组件、拒绝 reparse、使用 CreateNew 原子落盘 | 防止恶意文件被诱导写入系统路径 | QuarantineService、PathSafety | 高 | P0 | 目标目录或父级为 junction/symlink 时恢复拒绝；正常目录可恢复 | 已实施 |

## P1：核心安全能力

| 编号 | 升级名称 | 所属模块 | 当前问题与依据 | 竞品参考 | 改进方案 | 预期效果 | 文件/模块 | 难度 | 优先级 | 验收标准 | 状态 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| EV-007 | 扫描失败原因分类 | 扫描编排 | 平台错误、权限不足、超时和 Defender 不可用混在文本 warning | Wazuh/Velociraptor 事件类型 | 引入 ScanFailureKind、来源、重试性和覆盖影响 | 用户能判断是否重试或改范围 | Core.Models、ScanOrchestrator、报告 | 中 | P1 | 每种失败在 UI、数据库和报告中有稳定分类 | 计划 |
| EV-008 | Defender 健康快照 | Defender | 页面有状态但缺少检测时间、服务状态和读取失败原因的统一快照 | Microsoft Defender 控制台、ClamAV health | 持久化 engine/version/signature age/last error | 覆盖限制可追溯 | DefenderClient、security_events | 中 | P1 | Defender 不可用时显示明确原因，不计入安全评分分母 | 计划 |
| EV-009 | 扫描配置档案 | 扫描页 | Quick/Full/Custom 参数缺少可保存的用户档案 | ClamWin 计划扫描、Portmaster profiles | 保存扫描范围、排除、引擎、资源策略和显示偏好 | 重复扫描操作更快 | AppConfigData、ScanViewModel、SettingsPage | 中 | P1 | 新建/复制/删除档案，重启后仍能运行同一范围 | 计划 |
| EV-010 | 计划扫描 | 扫描/任务 | 当前只有手动入口，无法周期执行 | ClamWin scheduled scan、TinyWall profile | 用 Windows Task Scheduler 注册可见、可删除任务 | 降低遗忘扫描风险 | WindowsTasksAndServices、SettingsPage | 高 | P1 | 创建的任务可在系统任务计划程序中查看、取消和审计 | 计划 |
| EV-011 | 签名库更新策略 | Defender | 只能手动或随系统更新，缺少可见的更新时间和失败重试 | ClamAV FreshClam | 增加状态、频率、退避、最近成功/失败记录 | 病毒库新鲜度更透明 | DefenderClient、ConfigService、SettingsPage | 中 | P1 | 模拟网络失败后按退避重试，状态写入事件 | 计划 |
| EV-012 | 扫描排除安全管理 | 扫描设置 | 排除配置可输入任意路径，缺少关键目录阻止和解释 | YARA/端点工具的 explicit exclusions | 规范化、拒绝系统关键根、显示排除原因并支持导出 | 降低误排除造成的盲区 | PathSafety、SettingsPage、ConfigService | 中 | P1 | 关键系统目录不能加入排除；旧配置加载后被标记而不是静默生效 | 计划 |
| EV-013 | 多引擎适配接口 | Core/Platform | Defender 与 SmartRisk 在编排层耦合，未来接入 YARA 成本高 | ClamAV、HydraDragon 的多引擎编排 | 定义 IDetectionEngine、EngineCapabilities、CoverageNote | 可替换引擎且结果格式一致 | Core.Abstractions、ScanOrchestrator | 高 | P1 | 离线 fake engine 可并发运行；每条结果记录 engine/version/capability | 计划 |
| EV-014 | 可选 YARA 离线研究引擎 | 文件分析 | SmartRisk 规则有限，缺少用户可选的规则匹配能力 | YARA、YARA-X | 以规则目录和独立执行边界加入可选扫描，命中仅标为提示 | 增加研究能力而不把规则命中称为病毒 | Core/Platform、SettingsPage、规则目录 | 高 | P1 | 无规则时功能明确禁用；规则命中含规则 ID、来源、版本和证据 | 计划 |
| EV-015 | 威胁记录事件关联 | 数据/报告 | 威胁、扫描、事件已有表，但缺少统一 correlation ID 和规则来源 | Wazuh/Sigma 的 rule id/source | 增加 run、engine、rule、evidence、correlation 字段和索引 | 事件调查可从提示追到原始扫描 | AppDatabase、ThreatRepository、ReportData | 中 | P1 | 从报告中的任意威胁可查询到扫描、引擎和证据 | 计划 |
| EV-016 | 隔离库保留与清理 | 隔离库 | 只有单条操作，长期隔离文件没有容量/年龄策略 | ClamWin/桌面安全产品的 quarantine 管理 | 增加按年龄、大小和状态清理，默认预览后确认 | 控制磁盘占用，避免误删 | QuarantineService、MaintenancePage | 中 | P1 | 预览显示将删除条目，确认后只删除已选且有审计记录 | 计划 |

## P1：网络、启动项与系统检查

| 编号 | 升级名称 | 所属模块 | 当前问题与依据 | 竞品参考 | 改进方案 | 预期效果 | 文件/模块 | 难度 | 优先级 | 验收标准 | 状态 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| EV-017 | 网络事件过滤与时间线 | 网络页 | TCP 列表刷新后历史事件难以追溯，过滤粒度有限 | Portmaster/OpenSnitch | 保存连接事件、进程签名、域名/IP、首次/最近时间和依据 | 快速定位异常连接 | WindowsNetworkMonitor、NetworkPage、AppDatabase | 高 | P1 | 可按进程、签名、端口、严重性和时间筛选并导出 | 计划 |
| EV-018 | 防火墙规则模拟器 | 网络页 | 目前提示可疑连接但不能预览规则效果 | simplewall/TinyWall | 在本地构造规则候选并显示命中，不立即写入系统 | 用户先理解影响再决定 | NetworkViewModel、Core.Network | 中 | P1 | 输入规则后能显示命中连接和冲突；关闭页面不改变系统 | 计划 |
| EV-019 | 防火墙规则导入导出 | 网络页 | 规则无法迁移和审阅 | simplewall/Fort Firewall | 采用版本化 JSON，记录来源、作用域和回滚信息 | 便于备份和复核 | NetworkModels、NetworkPage | 中 | P1 | 导出文件可重新导入，非法字段被拒绝且不写系统 | 计划 |
| EV-020 | 启动项来源与变更历史 | 启动项 | 当前枚举项可见，但新增/修改原因缺少历史 | osquery/EDR event history | 对 Run/Startup 记录首次见到、签名、哈希、父目录和变更时间 | 提升启动项调查能力 | WindowsStartupManager、SQLite | 中 | P1 | 同一项重启后不重复制造事件；修改可追溯 | 计划 |
| EV-021 | 软件更新风险视图 | 软件管理 | 能列出软件和卸载入口，但不识别过期版本或安装来源 | Wazuh vulnerability inventory | 先做离线版本比较和来源标注，不静默下载 | 帮助用户决定更新优先级 | WindowsInstalledAppsProvider、SoftwarePage | 中 | P1 | 版本解析失败明确标注；无网络时仍可查看本地清单 | 计划 |
| EV-022 | 安全检查修复计划 | 系统安全 | 检查结果有建议，但没有按风险生成可确认的动作计划 | Wazuh remediation context | 把检查项映射为只读建议、可提权动作和外部说明 | 减少用户从结果到行动的跳转 | SystemSecurityCheckService、SystemSecurityPage | 中 | P1 | 每个动作显示影响、权限、回滚和确认；不可自动修复的项明确标注 | 计划 |

## P2：产品体验与可访问性

| 编号 | 升级名称 | 所属模块 | 当前问题与依据 | 竞品参考 | 改进方案 | 预期效果 | 文件/模块 | 难度 | 优先级 | 验收标准 | 状态 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| EV-023 | 评分可解释面板 | 驾驶舱 | 综合分数有规则，但用户需要逐项展开才能理解变化 | Wazuh alerts、Defender health | 显示有效分母、权重、状态、最近变化和不可读项 | 评分不再像黑箱 | DashboardViewModel、DashboardPage | 中 | P2 | 分数变化能定位到具体检查项和依据 | 计划 |
| EV-024 | 扫描空状态和失败恢复 | 扫描页 | 无历史、无路径、异常时的动作提示不统一 | ClamWin/现代桌面安全 UI | 为空、权限不足、取消、引擎不可用提供统一动作卡 | 减少“卡住”感 | ScanPage.xaml、ScanViewModel | 低 | P2 | 每个空/失败状态都有下一步操作，取消后可立即再次扫描 | 计划 |
| EV-025 | 首次运行向导 | 应用启动 | 14 个页面对新用户门槛高，能力边界需要先说明 | ClamShield/桌面安全产品 | 首次显示隐私、Defender 依赖、权限和扫描入口，可从设置重开 | 降低误解和误操作 | App.xaml.cs、OnboardingPage、ConfigService | 中 | P2 | 首次仅显示一次；设置可重新打开；不上传文件 | 计划 |
| EV-026 | 键盘导航与焦点 | WPF UI | 页面控件多，键盘顺序和可见焦点需系统审查 | Windows 原生设置、TinyWall | 补充 AutomationProperties、TabIndex、焦点样式和快捷键 | 提升无障碍和效率 | Views、Themes/Controls.xaml | 中 | P2 | 仅用键盘完成扫描启动、暂停、取消和页面切换 | 计划 |
| EV-027 | 高 DPI 与窗口缩放 | WPF UI | 已有 manifest，但复杂页面的缩放矩阵未覆盖 | Windows 安全中心 | 使用统一尺寸资源和最小窗口约束，检查 100/125/150/200% | 避免裁切和重叠 | MainWindow.xaml、Themes、Views | 中 | P2 | 四种缩放下无裁切，窗口拖拽和最大化状态正确 | 计划 |
| EV-028 | 深浅主题对比度审计 | 主题 | 主题已存在，颜色对比和状态色需要系统检查 | TinyWall/Portmaster | 对文本、告警、禁用、焦点和图表颜色做 WCAG 风格清单 | 提高可读性 | Themes/Palette.*.xaml、Controls.xaml | 低 | P2 | 关键文本和告警在两主题下可读，状态不只靠颜色 | 计划 |
| EV-029 | 报告证据折叠与脱敏 | 报告 | 报告内容多，路径/用户名等敏感信息需用户控制 | Velociraptor evidence collection | 增加摘要、展开证据、脱敏选项和生成时间 | 报告更适合共享 | ReportData、PdfReportExporter、ReportCenterPage | 中 | P2 | 选择脱敏后用户名、完整路径和日志细节不会泄露 | 计划 |

## P2：数据、性能与稳定性

| 编号 | 升级名称 | 所属模块 | 当前问题与依据 | 竞品参考 | 改进方案 | 预期效果 | 文件/模块 | 难度 | 优先级 | 验收标准 | 状态 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| EV-030 | SQLite 完整性与备份 | 数据层 | 有 WAL 和 schema version，但没有用户可见的 integrity_check/备份 | Wazuh/本地安全工具数据保护 | 增加 integrity_check、VACUUM 前提示、热备份和恢复校验 | 降低数据损坏后不可恢复风险 | AppDatabase、SettingsPage、tools | 中 | P2 | 对测试库执行损坏、备份、恢复；旧记录可读取 | 计划 |
| EV-031 | 数据保留策略 | 数据层 | 事件和扫描记录持续增长，当前只有部分事件清理 | osquery/Wazuh retention | 对事件、扫描、检查、维护记录分别配置天数/数量 | 控制数据库规模 | Repositories、ConfigService、SettingsPage | 中 | P2 | 达到策略后只清理过期记录并写入审计事件 | 计划 |
| EV-032 | 结构化错误事件 ID | 全平台 | 宽泛 catch 让问题只能靠中文消息和日志定位 | Sigma/Wazuh rule id | 定义稳定事件 ID、来源、重试性、敏感字段脱敏规则 | 支持排障和后续规则 | Core.Models、Serilog、各 Platform 服务 | 中 | P2 | 同类故障产生相同 ID；日志不含凭据和文件内容 | 计划 |
| EV-033 | 子进程取消与树清理 | PowerShell/Defender | 已有超时和 Kill，但部分调用的取消语义和残留进程仍需验证 | Velociraptor cancellable actions | 统一 ProcessTree、超时、退出码、stderr 摘要和取消状态 | 防止后台命令残留 | PowerShellRunner、DefenderClient、ElevationLauncher | 中 | P2 | 模拟长命令，取消后无子进程残留或明确报告无法终止 | 部分 |
| EV-034 | 扫描资源预算 | 扫描编排 | 批间延迟存在，但 CPU、内存和 IO 上限没有统一配置 | Portmaster/ClamAV service model | 增加并发度、批大小、暂停和空闲让出策略 | 长时间扫描更稳定 | ScanOrchestrator、AppConfigData | 中 | P2 | 大目录扫描内存有上限，调低预算不会丢失检测记录 | 计划 |
| EV-035 | 性能基线与回归 | 性能 | 只有实时卡片，没有稳定的启动、扫描、数据库基线 | Portmaster/ClamAV operational metrics | 增加离线 fixture 基准和 CI 趋势产物 | 发现升级导致的退化 | tools/benchmarks、CI、ScanOrchestrator | 中 | P2 | 固定 fixture 输出文件数、吞吐、峰值内存并能比较历史 | 计划 |

## P3：工程化、发布与生态

| 编号 | 升级名称 | 所属模块 | 当前问题与依据 | 竞品参考 | 改进方案 | 预期效果 | 文件/模块 | 难度 | 优先级 | 验收标准 | 状态 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| EV-036 | 安装包代码签名 | 发布 | 当前 Release 安装包没有项目证书，SmartScreen 可能警告 | Windows 商业安全工具、更新器 | 配置受保护证书、签名安装包/可执行文件，CI 只读取秘密 | 提供发布者身份，减少拦截 | release.yml、publish.ps1、证书配置 | 高 | P3 | 受控 Release 资产能通过 Authenticode 和时间戳校验 | 阻塞 |
| EV-037 | 安装/更新隔离验收 | 发布测试 | 单元测试不能证明 Inno Setup 替换、重启、卸载和保留数据 | Velopack/Squirrel acceptance | 在干净 VM 做旧版→新版、失败回滚、卸载保留数据矩阵 | 获得真实发布证据 | tools/UiSmoke、release checklist | 高 | P3 | 每个场景有日志、版本、退出码和截图；失败不误报成功 | 计划 |
| EV-038 | WPF UI Smoke 扩展 | UI 测试 | 现有 smoke 主要验证更新进度和离线数据流 | Windows UI automation | 加入启动、导航、空状态、主题、托盘恢复和取消扫描 | 发现绑定/布局回归 | tools/PcSecurityCenter.UiSmoke、Views | 中 | P3 | 在 Windows 会话下自动完成关键路径并保存日志 | 部分 |
| EV-039 | 版本与日志自动同步 | 文档/发布 | README 和安装日志曾出现当前版本不一致 | 各项目 release automation | 用校验脚本阻止 stale current version，历史条目不重写 | 降低发布文档错误 | tools/Validate-ReleaseMetadata.ps1、CI | 低 | P3 | 当前版本、安装器和 README 变更后脚本给出明确失败 | 已实施 |
| EV-040 | SBOM 与许可证清单 | 供应链 | 依赖版本写在 csproj，但没有每次构建的 SBOM/许可证快照 | Wazuh/企业安全工程 | 生成 SPDX/CycloneDX 与第三方许可证清单，发布为 artifact | 提高供应链审计能力 | CI、installer/LICENSES.md、tools | 中 | P3 | 每次 Release 有可下载 SBOM，新增依赖触发审阅 | 计划 |

## 近期执行顺序

1. 已完成 EV-001、EV-002、EV-003、EV-039，并以构建和测试验证。
2. 下一批先做 EV-004、EV-007、EV-015、EV-017、EV-030。
3. 有真实 Windows 测试机后再做 EV-010、EV-017、EV-018、EV-036、EV-037、EV-038。
4. YARA、WFP 写规则和驱动类能力必须在许可证、签名、回滚、性能和误报证据齐备后再进入实现。
