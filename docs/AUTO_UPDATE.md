# 自动更新说明

## 当前方案

PcSecurityCenter 使用自有的轻量更新器，继续沿用现有 Inno Setup 安装包，不引入会替换安装目录结构的大型更新框架。更新检查按以下顺序尝试：

1. GitHub Release 的 `update.json` 静态清单（包含版本、资产、大小和 SHA-256）。
2. GitHub Releases Atom feed（不依赖匿名 REST API 配额；安装包和 `SHA256SUMS.txt` 使用项目的稳定命名规则补齐）。
3. GitHub Releases REST API（兼容兜底，带 ETag）。
4. 本地缓存（明确显示“不是实时检查结果”，不会允许直接下载）。

下载与安装保持用户确认：只允许 HTTPS 的 `github.com` / `*.githubusercontent.com`，流式下载显示真实进度，失败最多重试 3 次，下载后验证字节数、SHA-256、发布清单/`SHA256SUMS.txt`，并再次校验后才启动 Inno Setup。失败时保留当前版本可用。

## 方案调研与选择

本项目对照了三个成熟的 Windows/.NET 更新方向：

| 方案 | 优点 | 不采用的原因 |
|---|---|---|
| Velopack | 面向现代 Windows 桌面应用，提供打包、差分/全量更新和回滚思路 | 需要改造当前 Inno Setup 安装模型和发布产物；对本项目当前版本属于较大迁移 |
| NetSparkleUpdater | .NET 原生、支持 appcast、签名校验和自定义 UI | 需要引入 appcast/签名密钥管理；当前项目已有下载、哈希和安装流程，直接替换会增加迁移风险 |
| Squirrel.Windows / WinSparkle | 经过长期使用的桌面更新模式，生态资料多 | Squirrel 的包格式和安装目录模型与现有 Inno Setup 不一致；WinSparkle 主要面向原生/跨平台集成 |

因此本项目选择“保留 Inno Setup + 自定义校验链”，只替换不可靠的版本来源并把发布元数据标准化。这样能修复当前的 GitHub 403 限流问题，同时不破坏已安装的 1.2.2 用户和现有安装目录。

## 发布流程

- `main` push 和 Pull Request 由 `ci.yml` 构建并运行测试。
- 推送形如 `v1.2.3` 的标签触发 `release.yml`。
- 工作流会校验标签与 `Directory.Build.props` 的 `<Version>` 一致，运行 `publish.ps1`，生成安装包、便携 ZIP、`SHA256SUMS.txt` 和 `update.json`，再用仓库内置的 `GITHUB_TOKEN` 创建 Release。
- 发布前检查安装包日志与 `docs/releases/release-notes.md` 是否同步。每个 Release 和清单中的版本说明由 `tools/Sync-ReleaseNotes.ps1` 从维护源导出，正文链接使用完整 GitHub 地址。
- 已存在的 Release 不会被覆盖；`gh release create` 会失败并保留日志，避免误删或替换资产。

示例：

```powershell
git switch main
git tag v1.2.3
git push origin v1.2.3
```

正式发布前应确认版本号、更新日志、测试和产物均已审阅。不要把 GitHub Token、签名私钥或证书提交到仓库。

## 安全状态与限制

- HTTPS、可信主机、路径穿越防护、文件大小、SHA-256、Authenticode 验证和安装前二次哈希校验已实现。
- 当前仓库没有代码签名证书，公开 Release 安装包仍可能显示 Windows SmartScreen 警告；这项能力标记为 **BLOCKED**，不能宣称已完成签名发布。
- 没有把 GitHub Token 嵌入客户端。匿名 REST API 受限时，静态清单和 Atom feed 仍可工作。
- 真实 Release 下载、安装和重启需要在具备网络、管理员权限和匹配 Windows 版本的测试机上验证；本地单元测试不能替代该外部验收。

## 故障排查

- 如果界面显示“在线更新源暂不可用”并注明缓存时间，说明本次没有得到实时结果；联网后重新点击“检查更新”。
- 如果下载校验失败，安装不会启动。检查 Release 是否同时包含安装包、`SHA256SUMS.txt` 和 `update.json`，并重新生成产物。
- 如果安装失败，旧版本不会被应用内代码删除；可从原安装包或 Release 资产重新安装。
