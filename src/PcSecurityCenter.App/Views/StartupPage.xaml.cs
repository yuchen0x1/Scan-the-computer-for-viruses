using System.Windows.Controls;
using PcSecurityCenter.App.ViewModels;

namespace PcSecurityCenter.App.Views;

public partial class StartupPage : UserControl
{
    public StartupPage(StartupSoftwareViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
