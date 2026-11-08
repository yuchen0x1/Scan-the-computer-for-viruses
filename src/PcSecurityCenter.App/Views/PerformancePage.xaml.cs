using System.Windows.Controls;
using PcSecurityCenter.App.ViewModels;

namespace PcSecurityCenter.App.Views;

public partial class PerformancePage : UserControl
{
    public PerformancePage(PerformanceViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
