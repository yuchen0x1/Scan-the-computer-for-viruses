using System.Windows.Controls;
using PcSecurityCenter.App.ViewModels;

namespace PcSecurityCenter.App.Views;

public partial class ProtectionPage : UserControl
{
    public ProtectionPage(ProtectionViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
