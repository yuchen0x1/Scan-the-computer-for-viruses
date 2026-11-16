# PROJECT_AUDIT.md

> 基线日期：2026-11-16（Asia/Shanghai）
> 审计对象：PcSecurityCenter，当前分支 main，基线提交 af00ff3（tag v1.2.6）。

## 1. 项目定位

PC Security Center 是一个只在 Windows 本地运行的桌面安全管理平台。它把 Microsoft Defender 官方接口、SmartRisk 规则、系统检查、网络观察、维护工具、文件分析、隔离库和更新中心统一到一个 WPF 界面中。

目标用户是希望在不上传文件内容的情况下查看系统安全状态、发起 Defender 扫描、审阅可疑文件并完成常规维护的 Windows 10/11 用户。产品当前更接近“本地安全控制台”，不是独立的内核级杀毒引擎，也没有替代 Defender 的能力。

## 2. 实际架构

| 层 | 实现 | 证据 |
|---|---|---|
| UI | WPF、MVVM、CommunityToolkit.Mvvm、WinForms NotifyIcon | src/PcSecurityCenter.App/、App.xaml.cs、14 个 Views/*Page.xaml |
| 应用服务 | 手工组装的 Microsoft.Extensions.DependencyInjection 容器、主题、更新、通知、PDF 报告 | src/PcSecurityCenter.App/Services/ |
| 领域核心 | 扫描编排、范围切分、文件枚举、SmartRisk、PE 分析、评分、更新模型 | src/PcSecurityCenter.Core/ |
| 数据 | Microsoft.Data.Sqlite，WAL，版本表和仓储 | src/PcSecurityCenter.Data/Database/AppDatabase.cs、Repositories/ |
| Windows 平台 | PowerShell 5.1、MpCmdRun/Defender cmdlet、WMI、注册表、WFP/TCP 表、WinVerifyTrust、UAC | src/PcSecurityCenter.Platform/ |
| 测试 | xUnit；核心、扫描可靠性、隔离库、更新解析、图标缓存和集成测试 | tests/PcSecurityCenter.Tests/ |
| 发布 | .NET 10 自包含 win-x64、Inno Setup、便携 ZIP、SHA256SUMS、GitHub Actions | publish.ps1、.github/workflows/、installer/ |

## 3. 已实现能力清单

1. 安全驾驶舱：安全评分、防护状态、性能卡片、事件和一键体检。
2. 病毒查杀：快速、全盘、自定义范围，暂停/继续/取消，SmartRisk 与 Defender 结果合并。
3. 威胁处理：本地隔离、删除、忽略、详情，隔离库使用 DPAPI 保护主密钥和 AES-CBC + HMAC。
4. 实时防护：启动项、临时目录新进程、Run 键、Defender 状态和资源轮询。
5. 网络安全：TCP 连接、进程关联、签名检查、代理/Hosts/DNS/防火墙只读观察。
6. 系统安全：Defender、Windows Update、UAC、Secure Boot、TPM、BitLocker、RDP、SMBv1 等检查。
7. 性能监控：CPU、GPU、内存、磁盘、网络和温度（硬件支持时）。
8. 系统维护：清理扫描、磁盘分析、SFC/DISM/chkdsk 只读检查、还原点。
9. 启动项管理：Run/RunOnce 与启动文件夹枚举，禁用采用可恢复的值改名。
10. 软件管理：卸载注册表枚举、签名检查和官方卸载入口。
11. 高级工具：系统信息、环境变量、电源模式、服务、适配器和隐私快捷入口。
12. 文件分析：SHA-256/SHA-1/MD5、PE 解析、签名、熵、EICAR 自检。
13. 安全报告：SQLite 汇总，HTML/PDF 导出。
14. 更新中心：静态清单、Atom、REST、缓存回退，用户确认下载/安装，SHA-256 和签名检查。

界面中出现的能力已逐项追溯到服务、数据或平台调用；不能由当前代码证明的内核防护、独立病毒库、云端信誉和真实安装端到端能力没有计入“已完成”。

## 4. 当前优势

- **能力覆盖宽**：把扫描、系统检查、网络观察、维护和报告放在同一个本地应用里。
- **边界声明清楚**：Defender 不可用、无法读取和 SmartRisk 可疑提示会显示覆盖限制，不把未知文件直接称为病毒。
- **危险操作有保护**：清理、隔离、禁用启动项和提权操作有确认或白名单脚本约束。
- **数据链可追溯**：扫描记录、威胁记录、检查结果、维护记录和事件都进入 SQLite。
- **离线可用**：核心枚举、评分、文件分析和报告不依赖上传；更新失败不会阻断应用启动。
- **已有回归基础**：基线测试 134 项；本轮增加 2 项路径重解析安全测试，当前为 136 项，覆盖扫描分区、取消、隔离篡改、PowerShell 参数和更新解析。

## 5. 发现的问题与证据

### P0：更新包在校验后仍存在可替换窗口（已修复）

UpdaterService.ApplyAndRestart 原先关闭哈希文件句柄后再启动安装程序，且下载目录位于临时目录。这样在校验和启动之间存在 TOCTOU 窗口。当前工作树已改为：

- 下载目录拒绝重解析点并设置当前用户、SYSTEM、Administrators ACL。
- 下载临时文件使用不可预测名称和 FileMode.CreateNew。
- 应用更新必须存在已验证的 SHA-256。
- 哈希、签名检查到 Process.Start 期间持续持有禁止写入/删除的句柄。
- 应用前重新检查路径、重解析点和 Authenticode 状态。

### P0：发布元数据曾经漂移（已修复）

基线时 Directory.Build.props 已是 1.2.6，但 Inno Setup 默认回退值和 README 当前发布示例仍是 1.2.5。这会让不带 /DAppVersion 的手工打包产生错误版本。本次发布候选已统一为 1.2.7，并新增 tools/Validate-ReleaseMetadata.ps1，CI 在测试前运行它。

### P1：更新信任根仍依赖同一 GitHub 发布链（未完成）

SHA-256 清单和安装包都来自同一仓库；仓库或发布权限被攻破时，攻击者可能同时替换安装包和清单。当前没有内置发布公钥，也没有固定发布者证书指纹。应增加签名清单和轮换策略后再宣称供应链认证完成。

### P1：真实系统工作流覆盖不足

本地测试不能证明真实 Defender 服务、UAC、WinVerifyTrust 吊销检查、托盘恢复、Inno Setup 替换和重启。UiSmoke 使用离线 Defender 替身，只能证明界面和数据流，不等价于真实杀毒引擎验收。

### P1：隔离恢复和提权结果仍需要受控机验收

本轮已将提权结果迁移到 ACL 受限的用户数据目录，并在隔离恢复前检查目标路径的重解析点。仍需要在受控 Windows 机器上验证 UAC 子进程、管理员写入权限、恶意 junction/symlink 和取消/超时后的清理行为；隔离源文件本身的并发替换保护也应继续收紧。

### P2：异常可观测性不均匀

扫描主流程会显示失败状态，但平台层仍有若干宽泛 catch (Exception)。部分读取失败只能在日志中看到，UI 不能区分“权限不足、接口不存在、超时、数据损坏和暂时失败”。后续应统一错误分类和事件 ID。

### P2：数据治理和依赖治理尚未自动化

数据库有 schema 版本，但缺少可操作的完整性检查、用户可见备份/恢复和保留策略；CI 没有 SBOM、依赖漏洞和许可证清单的自动产物。

## 6. 基线验证

以下命令在 Windows 工作区执行：

| 检查 | 命令 | 结果 |
|---|---|---|
| 构建 | dotnet build PcSecurityCenter.slnx -c Release --no-restore | PASS，0 警告、0 错误 |
| 测试 | dotnet test tests/PcSecurityCenter.Tests/PcSecurityCenter.Tests.csproj -c Release --no-build --nologo | PASS，136/136 |
| 发布元数据 | pwsh -NoProfile -File tools/Validate-ReleaseMetadata.ps1 | PASS，8 项 |
| UI Smoke | dotnet run --project tools/PcSecurityCenter.UiSmoke -- artifacts/verification/scan-new；另行运行 -- --update artifacts/verification/update-new | PASS：扫描页、重复扫描、SQLite 关联、筛选、明暗主题、更新进度和校验链均通过；仍不等价于真实 Defender/安装更新 |
| 真实 Defender/UAC/安装更新 | 受控测试机流程 | BLOCKED，当前工作区没有完整端到端证据 |

## 7. 成熟度判断

当前版本已经具备可运行的本地安全控制台骨架和较完整的业务闭环，代码质量和回归覆盖高于概念验证阶段。发布签名、更新信任根、真实 Defender/UAC/安装更新验收、故障分类和数据治理仍未达到可以无条件称为生产级安全产品的证据标准。

下一阶段应按 UPGRADE_ROADMAP.md 先处理 P0/P1，再扩大真实 Windows 验收矩阵。
