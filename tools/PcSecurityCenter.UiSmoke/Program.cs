using System.IO;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using System.Threading.Channels;
using PcSecurityCenter.App.Services;
using PcSecurityCenter.App.ViewModels;
using PcSecurityCenter.App.Views;
using PcSecurityCenter.Core.Abstractions;
using PcSecurityCenter.Core.Models;
using PcSecurityCenter.Core.Scanning;
using PcSecurityCenter.Data.Configuration;
using PcSecurityCenter.Data.Database;
using PcSecurityCenter.Data.Repositories;
using PcSecurityCenter.Platform.Security;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        var updateOnly = args.Length == 2 && args[0] == "--update";
        if (args.Length != 1 && !updateOnly) { Console.Error.WriteLine("Pass [--update] and a disposable output directory inside this repository."); return 2; }
        var root = Path.GetFullPath(args[updateOnly ? 1 : 0]);
        var repo = Path.GetFullPath(Environment.CurrentDirectory);
        if (!File.Exists(Path.Combine(repo, "PcSecurityCenter.slnx")) ||
            !root.StartsWith(repo + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
            (Directory.Exists(root) && Directory.EnumerateFileSystemEntries(root).Any()))
        { Console.Error.WriteLine("Use a NEW empty directory inside the repository, running from its root."); return 2; }
        Directory.CreateDirectory(root);
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        var exit = 1;
        var bindingLog = new StringWriter();
        PresentationTraceSources.DataBindingSource.Listeners.Add(new TextWriterTraceListener(bindingLog));
        PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.Warning;
        app.Dispatcher.BeginInvoke(async () =>
        {
            try
            {
                foreach (var resource in new[] { "Palette.Light.xaml", "Controls.xaml" })
                    app.Resources.MergedDictionaries.Add(new ResourceDictionary { Source = new Uri($"pack://application:,,,/PcSecurityCenter.App;component/Themes/{resource}") });
                if (updateOnly)
                {
                    await UpdateProgressChecks.RunAsync(root);
                    Check(string.IsNullOrWhiteSpace(bindingLog.ToString()), "no WPF update binding warnings: " + bindingLog);
                    exit = 0;
                    return;
                }
                var fixture = Path.Combine(root, "fixture");
                Directory.CreateDirectory(fixture);
                await File.WriteAllBytesAsync(Path.Combine(fixture, "invoice.pdf.exe"), [0x4d, 0x5a, 0, 0]);
                using var db = new AppDatabase(Path.Combine(root, "security.db"));
                var config = new ConfigService(Path.Combine(root, "config.json"));
                var threats = new ThreatRepository(db);
                var scans = new ScanRunRepository(db);
                var defender = new OfflineDefender();
                var dialogs = new TestDialogs();
                var vm = new ScanViewModel(new ScanOrchestrator(defender, new ScanRangeBuilder(), new SmartRiskEngine()),
                    defender, new QuarantineService(Path.Combine(root, "vault")), threats, scans,
                    new SecurityEventBus(new SecurityEventRepository(db)), dialogs, config);
                var page = new ScanPage(vm);
                page.Width = 1080; page.Height = 1200;
                var host = new Window { Content = page, Width = 1100, Height = 1240, Left = -20000, Top = -20000, ShowInTaskbar = false };
                host.Show();
                await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
                vm.CustomPaths.Add(fixture);
                var task = vm.StartCustomCommand.ExecuteAsync(null);
                Check(!vm.CanStartScan, "scan buttons disabled while running");
                await task;
                await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
                Check(vm.Threats.Count > 0, "real SmartRisk fixture detected");
                Check(!vm.IsScanning && vm.CanStartScan, "controls restored after persistence");
                Check(!vm.PauseCommand.CanExecute(null) && !vm.ResumeCommand.CanExecute(null) && !vm.CancelCommand.CanExecute(null), "terminal scan controls disabled");
                var count = vm.Threats.Count;
                await vm.StartCustomCommand.ExecuteAsync(null);
                await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
                Check(vm.Threats.Count == count, "repeat scan findings stay visible");
                var latest = scans.GetRecent();
                Check(latest.Count == 2, "both scans persisted");
                Check(latest.All(r => threats.GetRecent().Count(t => t.ScanRunId == r.Id) == r.ThreatsFound), "history and threat totals agree");
                Check(latest.All(r => r.Scope == fixture && r.UncoveredNotes.Contains("Defender")), "scope and coverage persisted");
                vm.ThreatSearch = "does-not-match";
                Check(vm.ThreatsView.IsEmpty, "search empty state");
                vm.ThreatSearch = "invoice";
                Check(!vm.ThreatsView.IsEmpty, "search by file name");
                vm.ConfirmedOnly = true;
                Check(vm.ThreatsView.IsEmpty, "confirmed-only excludes rule notices");
                vm.ConfirmedOnly = false;
                vm.ThreatSearch = "";
                var confirmed = new ThreatInfo { Engine = "MicrosoftDefender", Kind = DetectionKind.Confirmed, Name = "UI fixture only", FilePath = "fixture-only", DefenderThreatId = 12 };
                vm.Threats.Add(confirmed);
                await vm.QuarantineThreatCommand.ExecuteAsync(confirmed);
                Check(vm.Threats.Contains(confirmed) && confirmed.Status == ThreatStatus.Active && dialogs.LastInfo.Contains("Windows 安全中心"), "unsupported Defender action keeps active record");
                vm.Threats.Remove(confirmed);
                foreach (var theme in new[] { "Light", "Dark" })
                {
                    app.Resources.MergedDictionaries[0] = new ResourceDictionary { Source = new Uri($"pack://application:,,,/PcSecurityCenter.App;component/Themes/Palette.{theme}.xaml") };
                    page.Background = (Brush)app.Resources["BrushCard"];
                    page.Measure(new Size(1080, 1200)); page.Arrange(new Rect(0, 0, 1080, 1200)); page.UpdateLayout();
                    await Dispatcher.Yield(DispatcherPriority.Render);
                    var image = new RenderTargetBitmap(1080, 1200, 96, 96, PixelFormats.Pbgra32);
                    image.Render(page);
                    var png = new PngBitmapEncoder(); png.Frames.Add(BitmapFrame.Create(image));
                    using var output = File.Create(Path.Combine(root, $"scan-{theme.ToLowerInvariant()}.png"));
                    png.Save(output);
                }
                host.Close();
                Check(string.IsNullOrWhiteSpace(bindingLog.ToString()), "no WPF binding warnings: " + bindingLog);
                Console.WriteLine("PASS: WPF scan view, repeated real SmartRisk scan, SQLite linkage, filters, action safety, light/dark render.");
                exit = 0;
            }
            catch (Exception ex) { Console.Error.WriteLine(ex); }
            finally { app.Shutdown(); }
        });
        app.Run();
        return exit;
    }
    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
        Console.WriteLine("PASS: " + message);
    }
    private sealed class TestDialogs : IDialogService
    {
        public string LastInfo { get; private set; } = "";
        public Task InfoAsync(string title, string message) { LastInfo = title + message; return Task.CompletedTask; }
        public Task<bool> ConfirmAsync(string title, string message, string confirmText = "确认", bool danger = false) => Task.FromResult(false);
        public Task<(bool ok, string input)> PromptAsync(string title, string message, string defaultValue = "") => Task.FromResult((false, ""));
    }
    private sealed class OfflineDefender : IDefenderClient
    {
        public bool IsAvailable => false;
        public string? MpCmdRunPath => null;
        public Task<DefenderStatusInfo> GetStatusAsync(CancellationToken ct = default) => Task.FromResult(new DefenderStatusInfo());
        public Task<bool> UpdateSignaturesAsync(CancellationToken ct = default) => Task.FromResult(false);
        public Task<bool> StartQuickScanAsync(CancellationToken ct = default) => Task.FromResult(false);
        public Task<MpScanResult> ScanPathsAsync(IEnumerable<string> paths, CancellationToken ct) => throw new NotSupportedException();
        public Task<List<ThreatInfo>> GetThreatDetectionsAsync(CancellationToken ct = default) => Task.FromResult(new List<ThreatInfo>());
        public Task<bool> RemoveThreatAsync(long threatId, CancellationToken ct = default) => throw new NotSupportedException();
        public async IAsyncEnumerable<DirectoryScanResult> StreamScanDirectoriesAsync(ChannelReader<string> directories, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct) { await Task.CompletedTask; yield break; }
    }
}
