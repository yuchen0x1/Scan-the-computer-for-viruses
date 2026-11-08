using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;

namespace PcSecurityCenter.Core.SecurityChecks;

/// <summary>
/// 安全评分计算器。评分规则完全公开透明：
/// 每个检查项带权重，按状态折算得分，最后汇总为 0-100 分。
/// 无法读取（NotSupported / NoPermission / Error）的项不计入分母 —— 绝不因"读不到"而默认给高分或低分。
/// </summary>
public class ScoreCalculator : IScoreCalculator
{
    // 状态 -> 得分系数
    private static double Factor(CheckStatus status) => status switch
    {
        CheckStatus.Ok => 1.0,
        CheckStatus.Warning => 0.6,
        CheckStatus.Risk => 0.0,
        // 未知状态不评分也不扣分：不参与分母
        CheckStatus.NotSupported or CheckStatus.NoPermission or CheckStatus.Error => double.NaN,
        _ => double.NaN,
    };

    public SecurityScore FromChecks(IReadOnlyList<SecurityCheckItem> checks)
    {
        var result = new SecurityScore();
        if (checks.Count == 0)
        {
            result.Total = 0;
            result.Grade = "未知";
            result.Summary = "尚未执行系统安全检查，评分不可用。";
            return result;
        }

        double earned = 0, possible = 0;
        var byCategory = new Dictionary<string, (double earned, double possible)>();

        foreach (var c in checks)
        {
            var f = Factor(c.Status);
            if (double.IsNaN(f)) continue;
            earned += f * c.Weight;
            possible += c.Weight;
            var (e, p) = byCategory.TryGetValue(c.Category, out var cur) ? cur : (0, 0);
            byCategory[c.Category] = (e + f * c.Weight, p + c.Weight);
        }

        foreach (var (cat, (e, p)) in byCategory)
            result.CategoryScores[cat] = p > 0 ? (int)Math.Round(e * 100 / p) : 0;

        // 全部检查项不可读时不给分：既不虚高也不虚低，如实标注评分不可用
        if (possible <= 0)
        {
            result.Total = 0;
            result.Grade = "未知";
            result.Summary = "所有检查项均无法读取（权限不足/暂不支持），评分不可用。";
            return result;
        }

        var raw = earned / possible * 100.0;
        result.Total = (int)Math.Round(Math.Clamp(raw, 0, 100));
        result.Grade = result.Total switch
        {
            >= 90 => "优秀",
            >= 75 => "良好",
            >= 60 => "一般",
            >= 40 => "较差",
            _ => "危险",
        };
        result.Summary = result.Total switch
        {
            >= 90 => "系统防护状态良好，建议保持定期扫描。",
            >= 75 => "整体状态尚可，存在可改进项。",
            >= 60 => "存在明确风险项，建议尽快处理。",
            >= 40 => "存在高风险问题，请立即处理。",
            _ => "系统存在严重风险，请立即处理检查出的红项。",
        };
        return result;
    }
}
