# COMPETITOR_ANALYSIS.md

> 研究日期：2026-11-16（Asia/Shanghai）
> 方法：访问项目主页、官方仓库 README、目录/源码入口、许可证文件、Releases/提交活动页面；重点项目再对照架构和安全边界。没有把 README 的宣传语当成运行验证。项目许可证和活跃度应在实际引入代码前再次核对。

## 1. 研究对象

本次研究覆盖 16 个项目：9 个 Windows 或 Windows 相关项目，7 个跨平台/非 Windows 对照项目。它们分别代表本地扫描、Windows 防火墙、端点可见性、DFIR、检测规则、更新和企业安全平台等能力。研究结果用于设计和取舍，不表示要复制这些项目或引入其代码。

| 项目 / 官方仓库 | 覆盖与许可证（以仓库为准） | 实际实现重点 | 对本项目可借鉴点 | 不直接照搬的原因 |
|---|---|---|---|---|
| ClamWin Free Antivirus — https://github.com/clamwin/clamwin | Windows；GPL-2.0 | C++ GUI、ClamAV 按需扫描、计划任务、Explorer 右键、FreshClam 更新；官方明确没有 on-access 实时防护 | 扫描编排、右键入口、计划任务和签名库更新 | GPL 派生分发义务；引擎能力和现有 Defender 角色不同 |
| ClamAV — https://github.com/Cisco-Talos/clamav | 跨平台；GPL-2.0-only | C/C++ 扫描引擎、归档解析、FreshClam、命令行/服务接口 | 把引擎与 UI 解耦，建立可替换引擎适配层 | 不能把第二引擎未经资源和误报评估就接入默认扫描 |
| simplewall — https://github.com/henrypp/simplewall | Windows；GPL-3.0 | WFP 前端、按应用/服务规则、托盘操作、便携部署 | 低开销规则模型、白名单/学习流程、规则导入导出 | GPL-3.0；本项目当前是观察型网络页，不应静默改写防火墙 |
| Portmaster — https://github.com/Safing/portmaster | Windows/Linux；GPL-3.0 | Go 服务、Windows WFP 组件、按应用/域名/IP/国家策略、DoH/DoT、网络历史 | 服务与托盘 UI 分层、应用级策略、情报列表 | 内核/驱动与网络隐私产品范围远大于本项目，迁移成本高 |
| Fort Firewall — https://github.com/tnodir/fort | Windows；GPL-3.0 | 驱动、父进程/服务名/路径/端口规则、带宽限制和统计图 | 父进程粒度、流量统计和规则解释 | 驱动引入、维护和签名成本高；不能只做界面仿制 |
| TinyWall — https://github.com/pylorak/TinyWall | Windows；GPLv3 + 仓库内第三方声明 | 依赖 Windows 防火墙 API 的托盘型默认拒绝、白名单、学习模式、零遥测 | 快速托盘动作、低资源、可见的默认策略 | 混合许可证必须逐项保留声明；默认拒绝不符合当前“只读提示”定位 |
| HydraDragonAntivirus — https://github.com/HydraDragonAntivirus/HydraDragonAntivirus | Windows 研究型；许可证和依赖需逐文件复核 | ClamAV、YARA-X、机器学习、行为分析、Ghidra、Suricata、Sigma、OpenEDR/内核组件 | 多引擎编排、静态+动态研究模式、明确实验性限制 | 驱动兼容和稳定性限制明显；不能把实验性高权限路径放进默认产品 |
| ClamShield — https://github.com/orloxgr/ClamShield | Windows；新项目，许可证与依赖需复核 | ClamAV GUI、实时 shield、计划扫描、签名更新、DNS 保护、隔离和 VirusTotal 入口 | 现代 UI 包装成熟引擎，实时监控和隔离形成闭环 | 项目较新；外部云查询会改变本项目“本地不上传”的隐私承诺 |
| OpenSnitch — https://github.com/evilsocket/opensnitch | Linux；GPL-3.0 | 守护进程 + Qt GUI，首次连接决策、nftables/iptables/eBPF、规则持久化 | 连接事件解释、首次决策流程、事件统计管道 | 平台不同；Windows 应改用 WFP/ETW，不能移植 Linux 内核代码 |
| Wazuh — https://github.com/wazuh/wazuh | 跨平台；GPL-2.0 | Agent、规则、漏洞、文件完整性、日志与集中管理 | 事件标准化、规则 ID、审计记录和风险上下文 | 服务端/集群部署超出本地应用范围；需避免引入遥测和运维负担 |
| Velociraptor — https://github.com/Velocidex/velociraptor | 跨平台 DFIR；AGPL-3.0 | VQL 查询、客户端动作、采集和调查工作流 | 可取消的任务、可复用查询、调查证据链 | AGPL 和服务端架构复杂；只借鉴任务模型与证据结构 |
| osquery — https://github.com/osquery/osquery | Windows/macOS/Linux；多组件开源许可 | 把系统状态映射成 SQL 表，守护进程、事件订阅和配置 | 统一查询模型、状态快照与变更事件 | 不把第三方表直接复制进 SQLite；需评估权限、性能和许可证 |
| YARA — https://github.com/VirusTotal/yara | 跨平台；BSD-3-Clause | C 引擎和规则语言，用字符串/条件匹配恶意样本 | 作为可选离线规则引擎、规则版本和命中证据 | 规则库质量和误报需要维护；不把 YARA 命中直接等同病毒 |
| YARA-X — https://github.com/VirusTotal/yara-x | 跨平台；仓库许可证需核对 | Rust 重写的规则引擎和兼容方向，强调更现代的实现 | 规则编译、错误诊断和现代 API 方向 | 当前产品没有 Rust 运行时边界；先以外部可选进程或研究工具评估 |
| Sigma — https://github.com/SigmaHQ/sigma | 跨平台规则生态；Sigma 规则许可证按仓库/规则核对 | 通用日志检测规则格式、转换器和规则元数据 | 事件分类、规则来源、严重性和引用字段 | Sigma 是日志检测格式，不是文件扫描引擎；需把规则映射到本地事件 |
| OpenEDR — https://github.com/ComodoSecurity/openedr | Windows 端点检测；仓库许可证和驱动要求需复核 | 用户态与驱动级端点监控、事件采集和分析 | 进程/文件/网络事件关联，作为未来实时防护研究 | 驱动签名、稳定性和权限风险高；不在本轮默认集成 |
| Microsoft Defender 生态对照 | Windows 内置，闭源 | 官方引擎、病毒库、系统隔离和 Windows 安全中心 | 继续把 Defender 作为主病毒判定来源，记录 API/覆盖限制 | 闭源且受系统策略控制；本项目不能宣称替代它 |

## 2. 重点对标结论

### 扫描与检测

ClamWin/ClamAV 证明“引擎服务与用户界面分离”能降低产品层复杂度；YARA/YARA-X 证明规则引擎应有版本、来源、命中证据和误报边界。当前项目已有 Defender + SmartRisk 两条路径，但没有通用的引擎适配接口、规则包版本和独立命中证据模型。

**决定：**保留 Defender 为主引擎；把 YARA 作为 P2 的可选离线研究引擎；先抽象引擎能力和结果模型，再考虑第二引擎。

### 网络安全

simplewall、TinyWall、Fort Firewall 和 Portmaster 的共同优势是规则模型清楚、托盘入口快、规则与进程/服务关联。当前项目的 Network 页面主要是只读观察和可疑提示，安全边界更保守，但缺少过滤、事件历史和导出。

**决定：**先增加“模拟规则/解释/导出”和事件过滤，不直接改变系统防火墙默认策略。真正的 WFP 写规则列为独立的 P1/P2 项，必须有回滚和受控测试机。

### 端点可见性与调查

osquery、Wazuh、Velociraptor、Sigma、OpenEDR 的价值在于事件标准化、查询/规则元数据、证据留存和调查任务生命周期。当前项目有 security_events 和日志，但事件字段不够统一，也没有关联 ID、规则来源和查询耗时。

**决定：**先扩充本地事件模型和任务状态，增加可解释的事件 ID、来源、证据、采集时间和失败原因；不引入集中服务或驱动。

### 产品体验

ClamWin 的右键/计划任务、TinyWall 的托盘快速动作、OpenSnitch 的首次连接决策、Portmaster 的应用级策略都降低了常用操作成本。当前项目已有 14 个页面，信息较全，但首次使用路径、空状态、筛选和键盘导航仍不够完整。

**决定：**优先改造扫描配置、网络事件过滤、空状态和错误反馈；高级策略保持显式确认。

## 3. 可移植技术与许可证决策

| 技术方向 | 结论 | 处理方式 |
|---|---|---|
| GPL 扫描/防火墙实现 | 有参考价值，但静态链接或派生分发会带来义务 | 只读源码/架构；若调用独立进程，仍需保留许可证和发行说明 |
| YARA 规则引擎 | 适合离线研究和可选扫描 | 先做适配接口、规则来源和结果解释，不带第三方规则库 |
| Sigma 规则格式 | 适合事件分类，不直接用于 PE 扫描 | 增加本地事件字段后再做规则转换 |
| osquery SQL 状态模型 | 适合状态快照 | 重新实现最小查询，不复制实现或第三方表 |
| Portmaster/Fort 的驱动策略 | 研究价值高，当前不集成 | 等代码签名、驱动验证、回滚和性能基线齐备 |
| NetSparkle/Velopack 等更新思路 | 说明签名清单和回滚是成熟能力 | 当前保留 Inno Setup，先修复 TOCTOU；签名清单列为 P1 |
| Wazuh/Velociraptor 的集中管理 | 与当前本地定位不匹配 | 仅吸收事件/任务证据结构 |

## 4. 研究限制

- 本轮没有把 16 个项目全部克隆到本仓库，也没有把任何第三方代码复制进产品。
- “近期活跃”只表示在 2026-11-16 访问时仓库存在新提交、Release 或活跃维护信号，不是对未来维护的保证。
- 项目的许可证、第三方子目录和规则文件可能不同；真正集成前必须在提交级别保存许可证与 NOTICE 证据。
- Windows Defender、代码签名、驱动兼容和真实安装行为需要 Windows 受控测试机，不能用网页或单元测试替代。

## 5. 结论

最值得当前项目吸收的是：

1. 用 ClamAV/YARA 的“引擎与 UI 解耦”改造扫描边界。
2. 用 simplewall/TinyWall 的低成本托盘和规则解释改进网络页。
3. 用 osquery/Wazuh/Velociraptor/Sigma 的事件字段、来源、证据和任务状态提升可追溯性。
4. 用 Portmaster/Fort 的服务与 UI 分层思路规划未来网络策略。
5. 用成熟更新器的签名清单、回滚和安装验证补齐发布供应链。

不采用的方向是：未经签名的驱动、高权限默认防火墙写入、云端上传文件内容、把 SmartRisk/YARA 命中直接展示成病毒，以及没有许可证证据的代码复制。
