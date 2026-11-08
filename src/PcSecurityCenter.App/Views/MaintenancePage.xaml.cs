using System.Windows.Controls;
using PcSecurityCenter.App.ViewModels;

namespace PcSecurityCenter.App.Views;

public partial class MaintenancePage : UserControl
{
    public MaintenancePage(MaintenanceViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}

public partial class MaintenancePage
{
    // 附加到分部类：处理清理项勾选（更新预计释放空间）
    private void ItemChecked(object sender, System.Windows.RoutedEventArgs e)
        => (DataContext as PcSecurityCenter.App.ViewModels.MaintenanceViewModel)?.UpdateSelected();
}
