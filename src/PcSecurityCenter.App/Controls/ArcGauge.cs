using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;

namespace PcSecurityCenter.App.Controls;

/// <summary>
/// 环形仪表盘控件（自绘，用于综合安全评分展示）。支持平滑动画过渡。
/// </summary>
public class ArcGauge : Control
{
    private Arc? _trackArc;
    private Arc? _valueArc;
    private TextBlock? _scoreText;
    private TextBlock? _labelText;
    private TextBlock? _gradeText;

    public static readonly DependencyProperty ValueProperty = DependencyProperty.Register(
        nameof(Value), typeof(double), typeof(ArcGauge),
        new PropertyMetadata(0.0, OnValueChanged));

    public static readonly DependencyProperty MaxValueProperty = DependencyProperty.Register(
        nameof(MaxValue), typeof(double), typeof(ArcGauge),
        new PropertyMetadata(100.0, OnValueChanged));

    public static readonly DependencyProperty LabelProperty = DependencyProperty.Register(
        nameof(Label), typeof(string), typeof(ArcGauge),
        new PropertyMetadata("综合安全评分"));

    public static readonly DependencyProperty GradeProperty = DependencyProperty.Register(
        nameof(Grade), typeof(string), typeof(ArcGauge),
        new PropertyMetadata("", OnValueChanged));

    public double Value
    {
        get => (double)GetValue(ValueProperty);
        set => SetValue(ValueProperty, value);
    }

    public double MaxValue
    {
        get => (double)GetValue(MaxValueProperty);
        set => SetValue(MaxValueProperty, value);
    }

    public string Label
    {
        get => (string)GetValue(LabelProperty);
        set => SetValue(LabelProperty, value);
    }

    public string Grade
    {
        get => (string)GetValue(GradeProperty);
        set => SetValue(GradeProperty, value);
    }

    static ArcGauge()
    {
        DefaultStyleKeyProperty.OverrideMetadata(typeof(ArcGauge), new FrameworkPropertyMetadata(typeof(ArcGauge)));
    }

    public override void OnApplyTemplate()
    {
        base.OnApplyTemplate();
        _trackArc = GetTemplateChild("PART_TrackArc") as Arc;
        _valueArc = GetTemplateChild("PART_ValueArc") as Arc;
        _scoreText = GetTemplateChild("PART_ScoreText") as TextBlock;
        _labelText = GetTemplateChild("PART_LabelText") as TextBlock;
        _gradeText = GetTemplateChild("PART_GradeText") as TextBlock;
        if (_labelText != null) _labelText.Text = Label;
        UpdateVisual(true);
    }

    private static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var g = (ArcGauge)d;
        if (g._valueArc != null) g.UpdateVisual(false);
        else g.UpdateVisual(false);
    }

    private void UpdateVisual(bool immediate)
    {
        var pct = MaxValue > 0 ? Math.Clamp(Value / MaxValue, 0, 1) : 0;
        if (_scoreText != null) _scoreText.Text = ((int)Math.Round(Value)).ToString();
        if (_gradeText != null) _gradeText.Text = Grade;
        if (_labelText != null) _labelText.Text = Label;
        if (_valueArc == null) return;

        var brush = pct switch
        {
            >= 0.9 => (Brush)Application.Current.Resources["BrushOk"]!,
            >= 0.75 => (Brush)Application.Current.Resources["BrushAccent"]!,
            >= 0.6 => (Brush)Application.Current.Resources["BrushWarn"]!,
            _ => (Brush)Application.Current.Resources["BrushDanger"]!,
        };

        var anim = new DoubleAnimation
        {
            To = pct,
            Duration = immediate ? TimeSpan.Zero : TimeSpan.FromMilliseconds(900),
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };
        _valueArc.BeginAnimation(Arc.SweepFractionProperty, anim);
        var colorAnim = new ColorAnimation
        {
            To = ((SolidColorBrush)brush).Color,
            Duration = immediate ? TimeSpan.Zero : TimeSpan.FromMilliseconds(900),
        };
        // 用动画更新画刷颜色（复制一份避免污染全局资源）
        var dynamicBrush = _valueArc.Stroke as SolidColorBrush ?? new SolidColorBrush(Colors.Gray);
        if (dynamicBrush.IsFrozen || dynamicBrush == brush)
        {
            dynamicBrush = new SolidColorBrush(((SolidColorBrush)brush).Color);
            dynamicBrush.BeginAnimation(SolidColorBrush.ColorProperty, colorAnim);
            _valueArc.Stroke = dynamicBrush;
        }
        else
        {
            dynamicBrush.BeginAnimation(SolidColorBrush.ColorProperty, colorAnim);
        }
        if (_scoreText != null) _scoreText.Foreground = brush;
    }
}

/// <summary>弧形绘图元素。</summary>
public class Arc : FrameworkElement
{
    public static readonly DependencyProperty StartFractionProperty = DependencyProperty.Register(
        nameof(StartFraction), typeof(double), typeof(Arc),
        new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty SweepFractionProperty = DependencyProperty.Register(
        nameof(SweepFraction), typeof(double), typeof(Arc),
        new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty StrokeThicknessProperty = DependencyProperty.Register(
        nameof(StrokeThickness), typeof(double), typeof(Arc),
        new FrameworkPropertyMetadata(12.0, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty StrokeProperty = DependencyProperty.Register(
        nameof(Stroke), typeof(Brush), typeof(Arc),
        new FrameworkPropertyMetadata(Brushes.Cyan, FrameworkPropertyMetadataOptions.AffectsRender));

    public double StartFraction
    {
        get => (double)GetValue(StartFractionProperty);
        set => SetValue(StartFractionProperty, value);
    }

    public double SweepFraction
    {
        get => (double)GetValue(SweepFractionProperty);
        set => SetValue(SweepFractionProperty, value);
    }

    public double StrokeThickness
    {
        get => (double)GetValue(StrokeThicknessProperty);
        set => SetValue(StrokeThicknessProperty, value);
    }

    public Brush Stroke
    {
        get => (Brush)GetValue(StrokeProperty);
        set => SetValue(StrokeProperty, value);
    }

    protected override void OnRender(DrawingContext dc)
    {
        var w = ActualWidth;
        var h = ActualHeight;
        if (w <= 0 || h <= 0) return;
        var radius = Math.Min(w, h) / 2 - StrokeThickness / 2;
        var center = new Point(w / 2, h / 2);

        // 背景轨道（颜色跟随主题资源，切换亮/暗时自动更新）
        var trackBrush = Application.Current?.TryFindResource("BrushTrack") as Brush
                        ?? new SolidColorBrush(Color.FromArgb(38, 0x26, 0x32, 0x48));
        var trackPen = new Pen(trackBrush, StrokeThickness);
        trackPen.StartLineCap = PenLineCap.Round;
        trackPen.EndLineCap = PenLineCap.Round;
        dc.DrawArc(null, trackPen, center, radius, StartFraction * 2 * Math.PI - Math.PI / 2, 1.95 * Math.PI);

        // 值弧
        var sweep = SweepFraction * 1.95 * Math.PI;
        if (sweep > 0.001)
        {
            var pen = new Pen(Stroke, StrokeThickness);
            pen.StartLineCap = PenLineCap.Round;
            pen.EndLineCap = PenLineCap.Round;
            dc.DrawArc(null, pen, center, radius, StartFraction * 2 * Math.PI - Math.PI / 2, sweep);
        }
    }
}

/// <summary>DrawingContext 扩展：画弧。</summary>
public static class DrawingContextExtensions
{
    public static void DrawArc(this DrawingContext dc, Brush? fill, Pen pen, Point center, double radius, double startAngle, double sweepAngle)
    {
        if (sweepAngle <= 0) return;
        sweepAngle = Math.Min(sweepAngle, Math.PI * 2);
        var start = new Point(center.X + radius * Math.Cos(startAngle), center.Y + radius * Math.Sin(startAngle));
        var end = new Point(center.X + radius * Math.Cos(startAngle + sweepAngle), center.Y + radius * Math.Sin(startAngle + sweepAngle));
        bool largeArc = sweepAngle > Math.PI;
        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            ctx.BeginFigure(start, isFilled: false, isClosed: false);
            ctx.ArcTo(end, new Size(radius, radius), 0, largeArc, SweepDirection.Clockwise, isStroked: true, isSmoothJoin: true);
        }
        dc.DrawGeometry(fill, pen, geo);
    }
}
