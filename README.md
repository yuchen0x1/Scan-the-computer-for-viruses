# Scan the computer for viruses

> Windows 智能安全卫士 (PC Security Center)

一款集**病毒查杀、实时防护、系统安全检查、网络安全监控、性能分析、系统维护、文件分析、安全报告**于一体的 Windows 桌面安全管理平台。

> 技术栈：C# / .NET 10 LTS / WPF / MVVM (CommunityToolkit.Mvvm) / SQLite / Serilog / LiveCharts2 / QuestPDF / Windows API / WMI / Microsoft Defender 官方接口

---

## 功能总览（13 个页面）

| 模块 | 能力 | 数据来源 |
|---|---|---|
| 安全驾驶舱 | 综合安全评分（规则公开透明）、防护状态卡、CPU/GPU/内存/磁盘/网速实时卡片、最近安全事件、一键体检 | 真实检查项 + PerformanceCounter/WMI |
| 病毒查杀 | 快速/全盘/自定义三种扫描；暂停/继续/取消；进度/速度/文件数 | Microsoft Defender 官方引擎（PowerShell cmdlet + MpCmdRun）+ SmartRisk 智能风险规则引擎 |
| 威胁处理 | 隔离（优先）/删除/忽略/详情；AES-256 加密隔离区，SHA256 双重完整性校验，防篡改逃逸 | Defender 官方接口（Remove-MpThreat）+ 本地隔离库 |
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

## 安全与权限体系（最高优先级）

- 默认最小权限运行（manifest 为 asInvoker）；只有必要操作（SFC/DISM/chkdsk/还原点/计划任务/服务启停）经用户确认后触发 UAC，提权脚本走**白名单模板 + 环境变量传参**，杜绝命令注入。
- 危险操作（隔离/删除/清理/禁用启动项）全部二次确认 + 日志记录。
- 不会静默关闭 Defender/防火墙，不会上传任何文件内容或隐私数据，扫描结果可追溯（引擎、依据、时间、哈希全记录）。
- 隔离区：AES-256 加密 + 密文哈希与原文件哈希双重校验，被篡改的隔离数据**拒绝恢复**。

## 评分规则（公开透明）

每项检查带权重，按状态折算：通过=100%、注意=60%、风险=0%；**无法读取（权限不足/暂不支持/失败）的项不进入分母**——既不虚高也不虚低。汇总为 0-100 分：≥90 优秀 / ≥75 良好 / ≥60 一般 / ≥40 较差 / 其余危险。

## 检测能力如实声明

- 病毒判定完全依赖 Microsoft Defender 引擎与病毒库，本工具负责调度、展示与处理，**不能保证检出所有威胁**。
- SmartRisk 引擎只输出「可疑/提示」级风险（每条附可解释依据），**绝不把未知文件判定为病毒**。
- 全盘扫描逐目录交付 Defender 引擎执行，原生快速扫描另含系统内存区域；内存驻留检测、内核级防护不在能力范围内。
- 评分仅反映本工具定义检查项的量化结果，不代表系统绝对安全。

## 构建与运行

```bash
# 需要 .NET 10 SDK（本机安装于 C:\Users\lenmo\dotnet-setup\sdk10）
dotnet build PcSecurityCenter.slnx
dotnet test tests/PcSecurityCenter.Tests/PcSecurityCenter.Tests.csproj -c Release     # 46 个单元/集成/安全测试
dotnet publish src/PcSecurityCenter.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o publish/selfcontained
# 安装包：installer/PcSecurityCenter.iss（Inno Setup 6）
```

框架依赖运行需要安装 [.NET 10 Desktop Runtime]；安装包与绿色版均为自包含部署，无需额外运行时。

## 窗口与托盘

- 顶栏右上角为最小化、最大化/还原、关闭；窗口四角为 Windows 11 标准轻微圆角，最大化时自动取消圆角。
- 点击「关闭」不会退出程序，而是收进系统托盘（通知区域），实时防护继续在后台运行。
- 单击或双击托盘图标、或右键选「打开」可恢复窗口；只有右键菜单中的「退出」会真正结束进程并清理托盘图标。
- 顶部「最小化」仍是普通任务栏最小化，不进入托盘。

## 数据与日志

- 数据目录：`%APPDATA%\PcSecurityCenter\`（数据库 security.db、日志 logs\、报告 reports\、隔离库 Quarantine\）
- 卸载不会删除用户数据目录（可手动清理）。

## 许可

见 [LICENSES.md](installer/LICENSES.md)。第三方组件：.NET/MIT、CommunityToolkit.Mvvm/MIT、Serilog/Apache-2.0、LiveCharts2/MIT、QuestPDF 社区许可、SQLite Public Domain、Inno Setup（安装包制作工具，Inno Setup License）。
