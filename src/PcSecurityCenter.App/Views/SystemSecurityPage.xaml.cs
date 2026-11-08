using System.Windows.Controls;
using PcSecurityCenter.App.ViewModels;

namespace PcSecurityCenter.App.Views;

public partial class SystemSecurityPage : UserControl
{
    public SystemSecurityPage(SystemSecurityViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
