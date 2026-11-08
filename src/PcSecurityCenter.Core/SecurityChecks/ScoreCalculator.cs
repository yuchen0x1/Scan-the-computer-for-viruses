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

        // 活动威胁强扣分（在检查项之外独立计算）
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

        var raw = possible > 0 ? earned / possible * 100.0 : 0.0;

        // 威胁扣分：由检查项中的活动威胁检测项体现，这里额外按严重度扣减上限 30 分
        var threatPenalty = checks.Where(c => c.Id == "active-threats" && c.Status == CheckStatus.Risk)
            .Sum(_ => 0); // 占位：威胁数量扣分在检查服务生成检查项时已按数量折算，这里不再重复扣

        result.Total = (int)Math.Round(Math.Clamp(raw - threatPenalty, 0, 100));
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
