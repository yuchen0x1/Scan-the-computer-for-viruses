using System.Windows.Controls;
using PcSecurityCenter.App.ViewModels;

namespace PcSecurityCenter.App.Views;

public partial class AdvancedToolsPage : UserControl
{
    public AdvancedToolsPage(AdvancedToolsViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
