using System.Windows.Controls;
using PcSecurityCenter.App.ViewModels;

namespace PcSecurityCenter.App.Views;

public partial class ReportCenterPage : UserControl
{
    public ReportCenterPage(ReportCenterViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
