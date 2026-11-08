# 软件许可与第三方组件声明

## 本软件

Windows 智能安全卫士 (PC Security Center) — 供学习与个人使用。
本软件按"现状"提供，不含任何担保。使用者需自行承担使用风险。

## 第三方开源组件

| 组件 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| .NET 10 Runtime / WPF | 10.0.100 | MIT License | 运行时与 UI 框架 |
| CommunityToolkit.Mvvm | 8.4.0 | MIT License | MVVM 框架 |
| Microsoft.Extensions.Hosting | 10.0.0 | MIT License | 依赖注入 |
| Microsoft.Data.Sqlite (+ SQLitePCLRaw) | 10.0.0 / 2.1.13 | MIT License | 本地数据库 |
| Serilog / Sinks.File / Sinks.Console / Extensions.Hosting | 4.3 / 7.0 / 6.0 / 10.0 | Apache License 2.0 | 结构化日志 |
| LiveChartsCore.SkiaSharpView.WPF | 2.0.0-rc5.4 | MIT License | 性能图表 |
| QuestPDF | 2025.7.0 | QuestPDF Community License（年收入低于 100 万美元的组织可免费使用） | PDF 报告导出 |
| SkiaSharp（QuestPDF/LiveCharts2 依赖） | 3.x | MIT License | 图形渲染 |
| System.Management / PerformanceCounter / ServiceController | 10.0.0 | MIT License | Windows 系统接口 |
| SQLite | — | Public Domain | 数据库引擎 |
| Inno Setup | 6.7.3 | Inno Setup License | 安装包制作（非运行时组件） |

以上许可证全文可在各组件官方仓库获取。若本软件分发时未能附上某许可证全文，请以组件官方仓库版本为准。

## 隐私与合规

- 本软件不收集、不上传任何用户数据；所有网络访问仅限：
  1. Microsoft Defender 病毒库更新（经 Microsoft 官方接口，用户触发）
  2. Windows Update 待更新查询（经 Microsoft 官方 COM 接口，用户触发）
  3. 可选的哈希信誉查询（默认关闭，需用户配置 API Key）
