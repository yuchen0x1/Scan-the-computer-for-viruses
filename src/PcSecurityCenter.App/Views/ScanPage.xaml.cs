using System.Windows.Controls;
using PcSecurityCenter.App.ViewModels;

namespace PcSecurityCenter.App.Views;

public partial class ScanPage : UserControl
{
    public ScanPage(ScanViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
