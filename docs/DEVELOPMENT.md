# 开发与仓库维护

## 目录约定

- `src/`、`tests/`：应用源码和回归测试。
- `installer/`：Inno Setup 脚本、语言资源、使用说明和法律文本。安装器需要的许可证源文件与生成工具均应保留。
- `docs/`：当前架构、维护说明及版本历史。一次性的任务进度、审计评分、研究克隆和个人机器截图不纳入源码仓库。
- `tools/`：可重复使用的维护与验证工具；WPF 验证入口见 [UiSmoke](../tools/PcSecurityCenter.UiSmoke/README.md)。
- `publish/`、`artifacts/`、各项目的 `bin/obj`：可重新生成的本地输出，由 Git 忽略。安装包和便携版作为 GitHub Release 资产分发。
- 应用真实数据位于 `%APPDATA%\PcSecurityCenter`；它们不属于构建产物，清理仓库时不得删除。

`.evolution/`、`.workbuddy/` 等本地工具状态也被忽略。不要提交个人配置、数据库、隔离内容、日志、证书、私钥或凭证。`.gitignore` 不能清除过去提交过的文件；发现敏感信息应单独处理其历史与凭证，不可通过普通删除假定已清除所有副本。

## 更新日志

1. 只编辑 [docs/releases/release-notes.md](releases/release-notes.md)。按 `## v版本 — YYYY-MM-DD` 倒序排列，日期采用北京时间。
2. 以源码与 Release 记录为依据，区分已实现行为、验证证据和已知限制。整理旧版本时不补造测试结果。
3. 在仓库根目录执行 `pwsh -File tools/Sync-ReleaseNotes.ps1`，生成安装包内的 `installer/更新日志.md`。
4. 执行 `pwsh -File tools/Sync-ReleaseNotes.ps1 -Check`，确认两份一致；CI 和正式发布都会执行此检查。
5. 导出单版用于 GitHub Release：`pwsh -File tools/Sync-ReleaseNotes.ps1 -Version 1.2.4 -OutputFile artifacts/release-notes-1.2.4.md`。

版本正文中的链接应使用完整 GitHub 地址，使同一正文在仓库、GitHub Release 和更新清单中均可使用。README 只保留最新版摘要。

历史 Release 描述可在说明纠错时编辑；不覆盖已经发布的安装包、便携版和校验文件，也不移动旧标签。早期 v1.0.0 标签与首批安装/更新实现的时间差见该版本日志。

## 构建与发布

需要 Windows 与 .NET 10 SDK。`dotnet build PcSecurityCenter.slnx -c Release` 构建，测试命令及安全验证范围见根 README 和 UiSmoke 说明。

`publish.ps1` 先检查日志同步，再构建、测试、自包含发布并打包。发布输出关闭本项目的 PDB 调试符号，不含用户数据。GitHub 发布流程见 [自动更新说明](AUTO_UPDATE.md)。

本项目按 MIT 开源，托管程序集可反编译属于预期。现有安装包未签名；更新 SHA256 校验提供完整性比对，不等于独立发布者认证。真实安装、更新、UAC 和 Defender 工作流应在受控 Windows 测试机上验收。
