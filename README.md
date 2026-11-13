# Scan the computer for viruses

[![CI](https://github.com/yuchen0x1/Scan-the-computer-for-viruses/actions/workflows/ci.yml/badge.svg)](https://github.com/yuchen0x1/Scan-the-computer-for-viruses/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Windows 智能安全卫士 (PC Security Center)

一款集**病毒查杀、实时防护、系统安全检查、网络安全监控、性能分析、系统维护、文件分析、安全报告**于一体的 Windows 桌面安全管理平台。

> 技术栈：C# / .NET 10 LTS / WPF / MVVM (CommunityToolkit.Mvvm) / SQLite / Serilog / LiveCharts2 / QuestPDF / Windows API / WMI / Microsoft Defender 官方接口

---

## 最新更新

### v1.2.4（2026-11-13）

扫描统计、重复扫描结果与覆盖限制展示已修正；威胁列表新增搜索和确认威胁筛选，配置与隔离区增强并发保护。Defender 单条威胁处理请在 Windows 安全中心的保护历史记录中完成。

安装包与便携版见 [v1.2.4 发布页](https://github.com/yuchen0x1/Scan-the-computer-for-viruses/releases/tag/v1.2.4)。完整历史见 [docs/releases/release-notes.md](docs/releases/release-notes.md)；本次研究、修改和验证见 [升级报告](docs/evolution-2026-11-13.md)。

---

## 功能总览（14 个页面，含设置中心）

| 模块 | 能力 | 数据来源 |
|---|---|---|
| 安全驾驶舱 | 综合安全评分（规则公开透明）、防护状态卡、CPU/GPU/内存/磁盘/网速实时卡片、最近安全事件、一键体检 | 真实检查项 + PerformanceCounter/WMI |
| 病毒查杀 | 快速/全盘/自定义三种扫描；暂停投递/继续/取消；枚举进度/速度/文件数与引擎覆盖限制 | Microsoft Defender 官方引擎（PowerShell cmdlet + MpCmdRun）+ SmartRisk 智能风险规则引擎 |
| 威胁处理 | 本地风险隔离（优先）/删除/忽略/详情；Defender 记录引导至 Windows 安全中心；AES-256-CBC 加密 + HMAC-SHA256 认证（encrypt-then-MAC）隔离区，主密钥 DPAPI 保护，密文被篡改即拒绝恢复 | Windows 安全中心保护历史记录 + 本地隔离库 |
| 实时防护 | 启动文件夹监控（FileSystemWatcher 事件驱动）、Run 键变化、临时目录新进程、Defender 状态变化；低频轮询资源占用可控 | Windows API + 可配置轮询间隔 |
| 网络安全 | TCP 连接（进程关联/签名检查）、可疑连接提示（标注依据，不自动封禁）、防火墙配置、代理/Hosts/DNS 检查、实时流量 | GetExtendedTcpTable / Get-NetFirewallProfile / 注册表只读 |
| 系统安全 | Defender/防火墙/Windows Update/UAC/Secure Boot/TPM/BitLocker/安全中心/账户/RDP/补丁/SMBv1 等 15+ 项检查 | PowerShell/WMI/注册表只读；**无法读取的项如实标注「权限不足/暂不支持」，绝不默认显示安全** |
| 性能监控 | CPU/GPU/内存/磁盘/网速实时曲线与卡片；温度（硬件支持时）；刷新间隔可设 | PerformanceCounter / WMI / GlobalMemoryStatusEx / nvidia-smi 回退 |
| 系统维护 | 可清理项先扫描后清理（白名单目录、跳过使用中文件）、磁盘空间分析、SFC/DISM/chkdsk 只读检查（提权需确认）、还原点查看/创建 | 文件枚举 + 受控提权（白名单脚本） |
| 启动项管理 | 注册表 Run/RunOnce、启动文件夹枚举与风险标注；禁用采用「值改名」可恢复，不删数据 | 注册表只读 + 签名验证 |
| 软件管理 | 已安装软件只读枚举、数字签名检查、官方卸载入口（非静默卸载） | 卸载注册表 + WinVerifyTrust |
| 高级工具 | 系统信息、环境变量、电源模式、服务、适配器、隐私设置快捷入口（全部只读） | WMI/命令行只读 |
| 文件分析 | SHA256/SHA1/MD5、PE 头解析、数字签名验证、熵分析、EICAR 引擎自检；**全部本地完成，不上传任何内容** | 本地实现 + WinVerifyTrust |
| 安全报告 | 检查/扫描/威胁/维护/事件汇总，HTML 与 PDF 导出，如实标注覆盖范围与限制 | SQLite 聚合 |
| 更新中心 | 检测更新与更新日志同一入口；启动时只检查 GitHub 静态清单/Atom/REST，多级回退；下载与重启由用户明确触发；缓存结果明确标注 | GitHub Releases（update.json/Atom/ETag/缓存）/ 本地 更新日志.md |

## 安全与权限体系（最高优先级）

- 默认最小权限运行（manifest 为 asInvoker）；只有必要操作（SFC/DISM/chkdsk/还原点/计划任务/服务启停）经用户确认后触发 UAC，提权脚本走**白名单模板 + 环境变量传参**，杜绝命令注入。
- 危险操作（隔离/删除/清理/禁用启动项）全部二次确认 + 日志记录。
- 不会静默关闭 Defender/防火墙，不会上传任何文件内容或隐私数据，扫描结果可追溯（引擎、依据、时间、哈希全记录）。
- 隔离区：AES-256-CBC 加密 + HMAC-SHA256 认证（encrypt-then-MAC），主密钥经 DPAPI（CurrentUser）保护存盘；密文被篡改的隔离数据**拒绝恢复**。
- 自动更新：启动时只检查版本，不自动下载；用户确认下载后，安装包仅从 GitHub 官方主机下载，落盘前做文件名净化、字节数核对、SHA256 与发布附带 SHA256SUMS 比对、Authenticode 签名与吊销状态验证，安装前再次比对哈希防替换；扫描进行中应用更新会先要求确认。

## 评分规则（公开透明）

每项检查带权重，按状态折算：通过=100%、注意=60%、风险=0%；**无法读取（权限不足/暂不支持/失败）的项不进入分母**——既不虚高也不虚低。汇总为 0-100 分：≥90 优秀 / ≥75 良好 / ≥60 一般 / ≥40 较差 / 其余危险。

## 检测能力如实声明

- 病毒判定完全依赖 Microsoft Defender 引擎与病毒库，本工具负责调度、展示与处理，**不能保证检出所有威胁**。
- SmartRisk 引擎只输出「可疑/提示」级风险（每条附可解释依据），**绝不把未知文件判定为病毒**。
- 全盘扫描逐目录交付 Defender 引擎执行，原生快速扫描另含系统内存区域；内存驻留检测、内核级防护不在能力范围内。
- 评分仅反映本工具定义检查项的量化结果，不代表系统绝对安全。

## 构建与运行

```bash
# 需要 .NET 10 SDK
dotnet build PcSecurityCenter.slnx
dotnet test tests/PcSecurityCenter.Tests/PcSecurityCenter.Tests.csproj -c Release     # 运行全部自动化测试
dotnet publish src/PcSecurityCenter.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o publish/selfcontained
# 安装包：installer/PcSecurityCenter.iss（Inno Setup 6）
```

框架依赖运行需要安装 [.NET 10 Desktop Runtime]；安装包与绿色版均为自包含部署，无需额外运行时。

## 窗口与托盘

- 顶栏右上角为最小化、最大化/还原、关闭；窗口四角为 Windows 11 标准轻微圆角，最大化时自动取消圆角。
- 点击「最小化」或「关闭」都不会退出程序，而是收进系统托盘（通知区域），实时防护继续在后台运行；首次收起会弹出一次气泡提示。
- 系统级最小化（Win+↓、任务栏点击）同样收进托盘。
- 单击或双击托盘图标、或右键选「打开」可恢复窗口；只有右键菜单中的「退出」会真正结束进程并清理托盘图标。

## 扫描结果与验证边界

- 文件数是本工具安全枚举的文件数量，跳过不可访问路径及重解析点，不代表 Defender 内部实际检查数量。多个引擎的检测记录分别计数；一个文件可能对应多条记录。
- Defender 不可用或调用失败时，仍可展示 SmartRisk 结果，并持续显示覆盖限制；“结束”不表示机器安全。
- 暂停控制后续投递；已交付系统 Defender 服务的工作可能继续。取消本工具进程也不保证系统服务立即停止已有扫描。
- “忽略”仅标记这条历史记录，后续扫描仍会重新检查。Defender 官方 `Remove-MpThreat` 不支持单条 ThreatID 处理，因此本工具不会执行该全局清除命令。
- [本地验证入口与截图说明](tools/PcSecurityCenter.UiSmoke/README.md)提供真实 WPF 页面、SmartRisk 样本与 SQLite 关联检查。它使用离线 Defender 替身，不代表完整应用或真实杀毒引擎验收。

## 数据与日志

- 数据目录：`%APPDATA%\PcSecurityCenter\`（数据库 security.db、日志 logs\、报告 reports\、隔离库 Quarantine\）
- 卸载不会删除用户数据目录（可手动清理）。

## 安装、更新与发布

### 安装包
- 标准 Windows 安装程序（`PcSecurityCenter-Setup-1.2.4.exe`，基于 Inno Setup 6）：支持安装目录选择、桌面快捷方式、卸载程序与「控制面板-程序和功能」条目。安装过程不关闭系统防护、不设置隐蔽开机自启、不注册计划任务。
- 免安装便携版：`PcSecurityCenter-Portable-1.2.4.zip`，解压即用。
- 安装包与便携版均为**自包含部署**（.NET 10 运行时已内嵌），无需额外安装 .NET Desktop Runtime。
- 自 1.2.0 起要求 **Windows 10 2004 (build 19041) 及以上**（x64）；Windows 10 1809/1909 不再支持。
- 每个 Release 附带 `SHA256SUMS.txt`，可自行校验下载产物完整性。

### 内置自动更新（更新中心）
- 左侧导航「更新中心」将**检测更新**与**更新日志**整合在同一页面：在线时更新日志直接来自官方发布页，离线时回退到随安装包分发的本地记录。
- 启动时自动尝试检测 GitHub Releases 上的新版本；发现新版本后仅提示，用户在更新中心点击下载后才获取安装包。下载完成后界面顶部显示更新横幅，点击「立即更新」并确认后才会运行安装程序并重启应用；扫描进行中会显示中断提示，也可选择「稍后」。
- 更新检查与更新日志共用 Releases 数据，优先使用静态 `update.json` 和 Atom feed，REST API 仅作兜底；支持 ETag 与 10 分钟内请求复用。若在线来源不可用，会显示最近缓存的发布时间并明确注明并非实时检查，缓存结果不会允许直接下载。
- 所有网络操作带超时与异常保护，更新检测失败不会影响正常启动与使用。
- 更新包下载后必须通过完整性校验（SHA256 + 签名/吊销验证）才会执行，校验不过拒绝安装。
- 更新包下载失败会自动重试最多 3 次；发布清单中的 SHA256 可直接校验，未提供时回退到 `SHA256SUMS.txt`。
- 更新通道自 `v1.1.0` 起持续维护，后续版本可由用户确认后从官方发布页拉取并完成校验。

完整架构、发布工作流、故障处理和当前签名限制见 [docs/AUTO_UPDATE.md](docs/AUTO_UPDATE.md)。

### 发布构建
```bash
# 一键发布（推荐）：自动构建、测试、发布、打包、生成安装包与 SHA256SUMS
# 需 PowerShell 7（pwsh）；版本号统一由 Directory.Build.props 注入
pwsh publish.ps1
# 或手动：
# 1) 自包含发布
dotnet publish src/PcSecurityCenter.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o publish/selfcontained
# 2) 便携版 zip
Compress-Archive -Path publish/selfcontained/* -DestinationPath publish/PcSecurityCenter-Portable-1.2.4.zip
# 3) 安装包（需 Inno Setup 6）
iscc /DAppVersion=1.2.4 installer/PcSecurityCenter.iss
# 4) 创建 GitHub Release 并上传安装包、便携版与 SHA256SUMS
gh release create v1.2.4 -t "Windows 智能安全卫士 v1.2.4" --notes-file installer/更新日志.md publish/installer/PcSecurityCenter-Setup-1.2.4.exe publish/PcSecurityCenter-Portable-1.2.4.zip publish/SHA256SUMS.txt publish/update.json
```

## Star History

项目的 GitHub Star 增长趋势（图表由 Star History 提供）：

[![Star History Chart](https://api.star-history.com/svg?repos=yuchen0x1/Scan-the-computer-for-viruses&type=Date)](https://star-history.com/#yuchen0x1/Scan-the-computer-for-viruses&Date)

## 许可

本项目以 [MIT](LICENSE) 协议开源。第三方组件：.NET/MIT、CommunityToolkit.Mvvm/MIT、Serilog/Apache-2.0、LiveCharts2/MIT、QuestPDF 社区许可、SQLite Public Domain、Inno Setup（安装包制作工具，Inno Setup License）。免责声明与能力边界另见 [LicenseText.md](installer/LicenseText.md)。
