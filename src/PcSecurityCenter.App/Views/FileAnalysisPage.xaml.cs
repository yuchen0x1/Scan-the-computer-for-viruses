using System.Windows.Controls;
using PcSecurityCenter.App.ViewModels;

namespace PcSecurityCenter.App.Views;

public partial class FileAnalysisPage : UserControl
{
    public FileAnalysisPage(FileAnalysisViewModel vm)
    {
        InitializeComponent();
        DataContext = vm;
    }
}
