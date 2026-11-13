using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using PcSecurityCenter.App.Services;
using PcSecurityCenter.App.ViewModels;
using PcSecurityCenter.App.Views;

internal static class UpdateProgressChecks
{
    public static async Task RunAsync(string root)
    {
        // 本工具生成的无签名 PE，仅作为下载字节，不启动它；使用真实 WinVerifyTrust 策略。
        var payload = await File.ReadAllBytesAsync(typeof(UpdaterService).Assembly.Location);
        var hash = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
        var manifest = JsonSerializer.Serialize(new
        {
            version = "99.0.0", tag = "v99.0.0", channel = "stable", releaseNotes = "Fixture only",
            assets = new[] { new { name = "Setup-fixture.exe", downloadUrl = "https://github.com/fixture/repo/setup.exe", size = payload.Length, sha256 = hash } }
        });
        using var metadata = new HttpClient(new ReplyHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(manifest, Encoding.UTF8, "application/json")
        }));
        var stream = new ChunkStream(payload);
        var attempts = 0;
        using var downloadHttp = new HttpClient(new ReplyHandler(_ =>
        {
            attempts++;
            var attemptStream = attempts == 1 ? stream : new ChunkStream(payload);
            if (attempts > 1) attemptStream.Release();
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(attemptStream) };
        }));
        var updater = new UpdaterService(metadata, downloadHttp, Path.Combine(root, "downloads"),
            Path.Combine(root, "cache", "releases.json"), new Version(1, 2, 4));
        var vm = new UpdateViewModel(updater);
        await updater.CheckAsync(forceRefresh: true);
        var progress = new List<int>();
        var wrongThread = false;
        vm.PropertyChanged += (_, _) => wrongThread |= !Application.Current.Dispatcher.CheckAccess();
        var halfway = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        updater.DownloadProgressChanged += (_, percent) =>
        {
            progress.Add(percent);
            if (percent >= 50) halfway.TrySetResult();
        };
        // 与真实后台回调一致：进度事件来自线程池，界面更新必须调度回 WPF Dispatcher。
        var download = Task.Run(() => updater.DownloadAsync());
        try
        {
            await halfway.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
            Check(vm.DownloadProgress == 50, "bar reaches 50% before download finishes");
            Check(vm.StatusText.Contains("50%"), "download text reaches 50% with the bar");
            Check(!wrongThread, "update properties change on UI thread");
            var lateVm = new UpdateViewModel(updater);
            Check(lateVm.DownloadProgress == 50 && lateVm.StatusText.Contains("50%"), "opening the page during download restores current progress");
            await RenderAsync(new UpdatePage(vm), Path.Combine(root, "update-50-percent.png"));
            stream.Release();
            await download.WaitAsync(TimeSpan.FromSeconds(10));
            await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
            Check(updater.State == UpdateState.Ready && vm.CanApply && vm.DownloadProgress == 100,
                $"download reaches verified Ready state (state={updater.State}, progress={vm.DownloadProgress}, error={updater.LastError})");
            Check(vm.StatusText.Contains("已下载"), "terminal status replaces progress text");
            Check(updater.VerifiedSha256 == hash && File.ReadAllBytes(updater.DownloadedPath!).SequenceEqual(payload), "downloaded bytes and SHA256 match");
            Check(attempts == 1, "successful download needs one attempt");
            Check(progress.Distinct().Count() > 1, "multiple real byte progress values observed");

            // 下载到 100% 后仍须通过原有安全校验，不能仅凭进度允许安装。
            manifest = manifest.Replace(hash, new string('0', 64), StringComparison.Ordinal);
            await updater.CheckAsync(forceRefresh: true);
            await Task.Run(() => updater.DownloadAsync()).WaitAsync(TimeSpan.FromSeconds(20));
            await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
            Check(updater.State == UpdateState.Error && !vm.CanApply && !vm.IsDownloading,
                "hash mismatch remains an error and cannot install");
            Check(updater.DownloadedPath is null && updater.VerifiedSha256 is null && vm.StatusText.Contains("SHA256"),
                "failed download clears stale installer readiness and displays the error");
            Check(progress.Contains(0) && attempts == 4, "retry starts at 0% and remains bounded to 3 attempts");
        }
        finally
        {
            stream.Release();
            await download.WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    private static async Task RenderAsync(UserControl page, string output)
    {
        page.SetResourceReference(Control.BackgroundProperty, "BrushBgDeep");
        var host = new Window { Content = page, Width = 1100, Height = 950, Left = -20000, Top = -20000, ShowInTaskbar = false };
        try
        {
            host.Show();
            await Dispatcher.Yield(DispatcherPriority.ApplicationIdle);
            page.Measure(new Size(1080, 900)); page.Arrange(new Rect(0, 0, 1080, 900)); page.UpdateLayout();
            var bitmap = new RenderTargetBitmap(1080, 900, 96, 96, PixelFormats.Pbgra32);
            bitmap.Render(page);
            var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using var file = File.Create(output);
            encoder.Save(file);
        }
        finally { host.Close(); }
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
        Console.WriteLine("PASS: " + message);
    }

    private sealed class ReplyHandler(Func<HttpRequestMessage, HttpResponseMessage> reply) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(reply(request));
        }
    }

    private sealed class ChunkStream(byte[] bytes) : Stream
    {
        private int _position;
        private readonly TaskCompletionSource _continue = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Release() => _continue.TrySetResult();
        public override bool CanRead => true;
        public override bool CanSeek => false; // 刻意省略 Content-Length，验证使用发布资产的大小。
        public override bool CanWrite => false;
        public override long Length => bytes.Length;
        public override long Position { get => _position; set => throw new NotSupportedException(); }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (_position >= bytes.Length / 2) await _continue.Task.WaitAsync(ct);
            await Task.Delay(5, ct);
            var limit = _position < bytes.Length / 2 ? bytes.Length / 2 : bytes.Length;
            var count = Math.Min(Math.Min(4096, buffer.Length), limit - _position);
            bytes.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            return count;
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
