# CHANGELOG

## Unreleased — 2026-11-17

- WPF 应用壳层支持按 Windows UI 语言自动选择中文/English，并在标题栏提供持久化手动选择。
- 导航、窗口标题和托盘入口支持即时更新，扫描与威胁数据保持原样。

## 1.2.8 — 2026-11-17 多语言应用壳层

- 按 Windows UI 语言自动选择中文/English，标题栏支持手动切换和持久化。
- 导航、窗口标题和托盘入口即时更新；扫描与威胁数据保持原样。

## 1.2.7 — 2026-11-16 研究与安全加固

- 修复更新包在哈希校验后到启动安装器之间的 TOCTOU 窗口。
- 更新暂存目录拒绝重解析点，并在 Windows 上限制为当前用户、SYSTEM 和 Administrators。
- 下载临时文件改用不可预测名称与 CreateNew；应用更新前强制再次校验 SHA-256 和 Authenticode。
- 提权结果文件迁移到 ACL 受限的用户数据目录，并在隔离恢复前拒绝无法验证的重解析路径。
- 删除应用容器中重复的 WindowsTasksAndServices 注册。
- 统一 Inno Setup 默认版本、README 当前 Release 示例和 1.2.7 发布元数据。
- 新增发布元数据校验工具，并接入 CI。
- 新增 PROJECT_AUDIT.md、COMPETITOR_ANALYSIS.md、UPGRADE_ROADMAP.md 和 UPGRADE_REPORT.md。
- 竞品研究覆盖 16 个开源项目；没有复制第三方代码或规则。
- 已知限制：公开 Release 仍没有代码签名；签名清单、真实 Defender/UAC/安装更新验收和恶意重解析点专门回归仍在路线图中。

## 历史版本

完整历史见 docs/releases/release-notes.md。
