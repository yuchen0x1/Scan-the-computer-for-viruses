using System.Windows.Controls;
using PcSecurityCenter.App.ViewModels;

namespace PcSecurityCenter.App.Views;

public partial class NetworkPage : UserControl
{
    public NetworkPage(NetworkViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
