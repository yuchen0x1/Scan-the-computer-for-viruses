using System.Windows.Controls;
using PcSecurityCenter.App.ViewModels;

namespace PcSecurityCenter.App.Views;

public partial class UpdatePage : UserControl
{
    public UpdatePage(UpdateViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
