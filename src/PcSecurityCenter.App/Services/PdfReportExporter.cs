using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Core.Reporting;
using PcSecurityCenter.Core.Utils;

namespace PcSecurityCenter.App.Services;

/// <summary>PDF 报告导出（QuestPDF，中文使用微软雅黑系统字体）。</summary>
public static class PdfReportExporter
{
    static PdfReportExporter()
    {
        QuestPDF.Settings.License = LicenseType.Community;
    }

    public static void Export(ReportData data, string outputPath)
    {
        Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(36);
                page.DefaultTextStyle(x => x.FontFamily("Microsoft YaHei").FontSize(9.5f).FontColor("#334155"));

                page.Header().Column(col =>
                {
                    col.Item().Text("Windows 智能安全卫士 · 安全报告").FontSize(20).Bold().FontColor("#0EA5E9");
                    col.Item().Text($"生成时间：{data.GeneratedAt:yyyy-MM-dd HH:mm:ss}    主机：{data.MachineName}    系统：{data.OsName}")
                        .FontSize(9).FontColor("#64748B");
                });

                page.Content().PaddingVertical(10).Column(col =>
                {
                    col.Spacing(12);

                    // 评分
                    if (data.Score != null)
                    {
                        col.Item().Background("#F1F5F9").Padding(10).Row(row =>
                        {
                            row.RelativeItem().Column(c =>
                            {
                                c.Item().Text($"综合评分：{data.Score.Total}（{data.Score.Grade}）").FontSize(14).Bold();
                                c.Item().Text(data.Score.Summary).FontSize(9);
                            });
                            row.ConstantItem(120).Column(c =>
                            {
                                foreach (var (cat, val) in data.Score.CategoryScores)
                                    c.Item().Text($"{cat}：{val}").FontSize(9);
                            });
                        });
                    }

                    // 检查明细
                    col.Item().Text("系统安全检查明细").FontSize(13).Bold().FontColor("#0EA5E9");
                    if (data.Checks.Count > 0)
                    {
                        col.Item().Table(t =>
                        {
                            t.ColumnsDefinition(c =>
                            {
                                c.ConstantColumn(120);
                                c.ConstantColumn(50);
                                c.RelativeColumn();
                            });
                            t.Header(h =>
                            {
                                h.Cell().Element(HeadCell).Text("项目").FontColor("#E2E8F0").Bold();
                                h.Cell().Element(HeadCell).Text("状态").FontColor("#E2E8F0").Bold();
                                h.Cell().Element(HeadCell).Text("结果 / 建议").FontColor("#E2E8F0").Bold();
                            });
                            foreach (var c in data.Checks)
                            {
                                t.Cell().Element(BodyCell).Text(c.Name);
                                t.Cell().Element(BodyCell).Text(c.Status switch
                                {
                                    CheckStatus.Ok => "通过",
                                    CheckStatus.Warning => "注意",
                                    CheckStatus.Risk => "风险",
                                    CheckStatus.Error => "失败",
                                    CheckStatus.NotSupported => "不支持",
                                    CheckStatus.NoPermission => "权限不足",
                                    _ => "未知",
                                }).FontColor(c.Status switch
                                {
                                    CheckStatus.Ok => "#16A34A",
                                    CheckStatus.Warning => "#D97706",
                                    CheckStatus.Risk => "#DC2626",
                                    _ => "#64748B",
                                });
                                t.Cell().Element(BodyCell).Text(string.IsNullOrEmpty(c.Recommendation) ? c.Result : $"{c.Result}；建议：{c.Recommendation}");
                            }
                        });
                    }

                    // 扫描记录
                    col.Item().Text("扫描记录").FontSize(13).Bold().FontColor("#0EA5E9");
                    foreach (var s in data.Scans.Take(30))
                        col.Item().Text($"{s.StartedAt:yyyy-MM-dd HH:mm} [{ScanTypeName(s.Type)}] {s.FinalState}，文件 {s.FilesScanned}，风险 {s.ThreatsFound}，引擎 {s.Engines}")
                            .FontSize(9);

                    // 威胁
                    col.Item().Text("威胁与风险记录").FontSize(13).Bold().FontColor("#0EA5E9");
                    foreach (var t in data.Threats.Take(50))
                        col.Item().Text($"[{t.Severity}] {t.Name} —— {t.FilePath}\n    引擎 {t.Engine}；依据：{t.Evidence}；状态：{t.Status}").FontSize(9);
                    if (data.Threats.Count == 0)
                        col.Item().Text("（无威胁记录）").FontSize(9).FontColor("#94A3B8");

                    // 维护记录
                    col.Item().Text("系统维护记录").FontSize(13).Bold().FontColor("#0EA5E9");
                    foreach (var m in data.MaintenanceRuns.Take(30))
                        col.Item().Text($"{m.StartedAt:yyyy-MM-dd HH:mm} {m.Action} —— {(m.Success ? "成功" : "失败")}，释放 {SizeFormat.Format(m.FreedBytes)}").FontSize(9);

                    // 事件
                    col.Item().Text("最近安全事件").FontSize(13).Bold().FontColor("#0EA5E9");
                    foreach (var e in data.Events.Take(50))
                        col.Item().Text($"{e.CreatedAt:MM-dd HH:mm:ss} [{e.Severity}] {e.Title} —— {e.Detail}").FontSize(8.5f);

                    // 免责与覆盖范围
                    col.Item().PaddingTop(14).Background("#F8FAFC").Padding(10).Column(c =>
                    {
                        c.Item().Text("覆盖范围与限制（如实说明）").Bold().FontSize(10);
                        c.Item().Text("本报告仅包含本工具实际执行的检查与扫描结果。病毒检测能力取决于 Microsoft Defender 病毒库与引擎，" +
                            "无法保证检测出所有威胁；内核级检测、网络流量深度分析不在本工具能力范围。评分反映本工具定义检查项的量化结果，不代表系统绝对安全。" +
                            "全部数据来自本机接口，报告生成不包含任何上传行为。").FontSize(8.5f).FontColor("#64748B");
                    });
                });

                page.Footer().AlignCenter().Text(t =>
                {
                    t.Span("第 ").FontSize(8).FontColor("#94A3B8");
                    t.CurrentPageNumber().FontSize(8);
                    t.Span(" 页 · Windows 智能安全卫士").FontSize(8).FontColor("#94A3B8");
                });
            });
        }).GeneratePdf(outputPath);
    }

    private static string ScanTypeName(ScanType t) => t switch
    {
        ScanType.Quick => "快速扫描", ScanType.Full => "全盘扫描", _ => "自定义扫描",
    };

    private static IContainer HeadCell(IContainer c) => c.Background("#0F172A").Padding(5);
    private static IContainer BodyCell(IContainer c) => c.BorderBottom(0.5f).BorderColor("#E2E8F0").Padding(5);
}
