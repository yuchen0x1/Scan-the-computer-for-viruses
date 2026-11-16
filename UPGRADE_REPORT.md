# UPGRADE_REPORT.md

> 交付日期：2026-11-16（Asia/Shanghai）
> 对象：PcSecurityCenter v1.2.7 发布候选升级。

## A. 竞品研究

- 实际研究：16 个开源项目，覆盖 ClamWin、ClamAV、simplewall、Portmaster、Fort Firewall、TinyWall、HydraDragonAntivirus、ClamShield、OpenSnitch、Wazuh、Velociraptor、osquery、YARA、YARA-X、Sigma 和 OpenEDR。
- 重点借鉴：ClamAV/YARA 的引擎边界，simplewall/TinyWall 的低成本网络交互，Portmaster/Fort 的策略分层，Wazuh/Velociraptor/Sigma 的事件和规则证据，成熟更新器的签名清单思路。
- 本项目当前优势：本地处理、Defender 官方引擎、扫描/隔离/报告闭环、公开评分规则、当前 136 项自动化测试。
- 明显短板：没有独立发布签名和签名清单信任根，真实 Defender/UAC/安装更新验收不足，隔离恢复和提权回传还缺少恶意重解析点的专门回归，事件错误分类和数据保留策略不完整。
- 合规决定：本轮只阅读仓库、README、目录和实现方向；没有复制第三方代码、规则或许可证文本。GPL/AGPL 项目仅作为架构参考，未来集成必须单独做许可证审阅。

详细对标见 COMPETITOR_ANALYSIS.md。

## B. 升级数量与状态

| 状态 | 数量 | EV 编号 |
|---|---:|---|
| 已实施 | 6 | EV-001、EV-002、EV-003、EV-005、EV-006、EV-039 |
| 部分完成 | 2 | EV-033、EV-038 |
| 未完成但已确认有价值 | 31 | EV-004、EV-007 至 EV-032、EV-034、EV-035、EV-037、EV-040 |
| 阻塞 | 1 | EV-036 |
| 合计 | 40 | EV-001 至 EV-040 |

“部分完成”表示已有底层能力或测试入口，但缺少完整验收闭环；“阻塞”不是代码完成标记。EV-036 需要真实发布证书和受保护的 CI 秘密。

逐项的当前问题、依据、参考、文件、难度、优先级和验收标准见 UPGRADE_ROADMAP.md。

## C. 本轮代码与文档修改

### 修改的现有文件

- src/PcSecurityCenter.App/Services/UpdaterService.cs
  - 更新目录拒绝重解析点并设置受限 ACL。
  - 下载临时文件改用随机名称和 FileMode.CreateNew。
  - 应用更新强制存在已验证 SHA-256，检查路径和重解析点。
  - 哈希、签名验证和启动安装器期间持续持有禁止写入/删除的文件句柄。
  - 应用前再次验证 Authenticode；失败则不启动。
- src/PcSecurityCenter.App/App.xaml.cs
  - 删除重复的 WindowsTasksAndServices singleton 注册。
- src/PcSecurityCenter.Platform/Security/WindowsPermissionService.cs
  - 将提权结果文件移出共享 TEMP，改为用户数据目录、受限 ACL 和 CreateNew。
- src/PcSecurityCenter.Core/Utils/PathSafety.cs
  - 新增现有路径组件重解析点检查，并在无法验证时按不安全处理。
- src/PcSecurityCenter.Platform/Security/QuarantineService.cs
  - 恢复隔离文件前拒绝包含重解析点或无法验证的目标路径。
- tests/PcSecurityCenter.Tests/CoreLogicTests.cs
  - 增加普通路径和非法路径的重解析点安全回归测试。
- installer/PcSecurityCenter.iss
  - 默认回退版本由 1.2.5 修正为 1.2.7。
- README.md
  - 当前摘要、安装包、便携版和 Release 示例统一到 v1.2.7。
- .github/workflows/ci.yml
  - 增加发布元数据一致性检查步骤。

### 新增文件

- tools/Validate-ReleaseMetadata.ps1
- PROJECT_AUDIT.md
- COMPETITOR_ANALYSIS.md
- UPGRADE_ROADMAP.md
- UPGRADE_REPORT.md
- CHANGELOG.md

### 删除文件

- 无。

### 数据库、配置和 API 迁移

- 无数据库 schema 迁移。
- 没有删除或覆盖用户数据。
- 更新暂存目录策略发生了安全收紧：已有目录在下次更新检查/下载时会被重新检查并设置 ACL；重解析点会被拒绝。
- 配置文件格式未变更，旧配置保持兼容。

## D. 测试结果

| 检查 | 命令 | 结果 |
|---|---|---|
| Release 构建 | dotnet build PcSecurityCenter.slnx -c Release --no-restore | PASS，0 警告、0 错误 |
| 自动化测试 | dotnet test tests/PcSecurityCenter.Tests/PcSecurityCenter.Tests.csproj -c Release --no-build --nologo | PASS，136/136 |
| 发布元数据 | pwsh -NoProfile -File tools/Validate-ReleaseMetadata.ps1 | PASS，8 项 |
| 更新安全修复编译 | dotnet build src/PcSecurityCenter.App/PcSecurityCenter.App.csproj --no-restore | PASS，0 警告、0 错误 |
| UI Smoke | dotnet run --project tools/PcSecurityCenter.UiSmoke -c Release -- artifacts/verification/scan-new；另行运行 -- --update artifacts/verification/update-new | PASS：扫描页和更新页输出全部断言通过；使用离线 Defender 替身，不等价于真实 Defender/安装更新 |
| 真实 Defender/UAC/安装器 | 受控 Windows 测试机 | BLOCKED：当前工作区没有完整端到端证据 |
| 发布签名 | Authenticode/证书 | BLOCKED：没有可用的发布证书和时间戳配置 |

基线测试曾因同时启动 build 与 test 造成输出 DLL 文件锁而失败；随后改为顺序执行，最终构建和 136 项测试均通过。这是执行方式冲突，不是代码测试失败。

## E. 项目变化

### 升级前

- 功能覆盖已经较广，但更新安装路径存在校验后替换窗口。
- 版本号来源在构建文件、安装器 fallback 和 README 示例之间漂移。
- CI 检查构建、日志同步和测试，但不会阻止当前版本示例过期。
- 研究材料主要分散在历史文件，缺少当前项目审计、竞品对标和可执行路线图。

### 升级后

- 更新器把下载目录、临时文件、路径、哈希、签名和启动顺序纳入同一安全边界。
- 当前版本示例、安装器 fallback 和 CI 元数据校验统一到 1.2.7。
- 容器配置移除了重复注册。
- 仓库新增基于真实代码证据的审计、16 项竞品研究、40 项升级路线图和交付报告。
- 当前仍未宣称代码签名、签名清单信任根、真实安装更新、真实 Defender 和 UAC 端到端已经完成。

## F. 下一阶段

1. 先实现 EV-004、EV-005、EV-006 的供应链、提权和隔离恢复加固。
2. 再实现 EV-007、EV-015、EV-017 的错误分类、事件关联和网络时间线。
3. 在受控 Windows 虚拟机完成 EV-036、EV-037、EV-038；取得证书后再处理安装包签名。
4. 对 YARA、WFP 写规则、驱动和集中管理方向保持可选、显式和可回滚，不把研究型能力默认打开。
