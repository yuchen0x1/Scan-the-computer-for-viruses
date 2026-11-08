using System.Windows.Controls;
using PcSecurityCenter.App.ViewModels;

namespace PcSecurityCenter.App.Views;

public partial class SoftwarePage : UserControl
{
    public SoftwarePage(StartupSoftwareViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
