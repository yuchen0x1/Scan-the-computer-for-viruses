; Windows 智能安全卫士 安装包脚本（Inno Setup 6）
; 安全声明：本安装程序不关闭系统防护、不设置隐蔽开机自启、不注册任何计划任务。

#define AppName "Windows 智能安全卫士"
#define AppNameEn "PC Security Center"
#ifndef AppVersion
  #define AppVersion "1.2.0"
#endif
#define AppExe "PcSecurityCenter.App.exe"
#define PublishDir "..\publish\selfcontained"

[Setup]
AppId={{7C1F5E42-9A3B-4C6D-8E5A-1F2B3C4D5E6F}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=PC Security Center Team
DefaultDirName={autopf}\PcSecurityCenter
DefaultGroupName={#AppName}
UninstallDisplayName={#AppName} {#AppVersion}
UninstallDisplayIcon={app}\{#AppExe}
OutputDir=..\publish\installer
OutputBaseFilename=PcSecurityCenter-Setup-{#AppVersion}
SetupIconFile=..\src\PcSecurityCenter.App\Assets\app.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
PrivilegesRequired=admin
; 目标框架 net10.0-windows10.0.19041.0 要求 Windows 10 2004 (build 19041) 及以上
MinVersion=10.0.19041
LicenseFile=LICENSE.rtf
; 安装前信息使用纯文本（.md 会被原样显示 Markdown 符号）
InfoBeforeFile=安装前信息.txt
ChangesAssociations=no
; 不创建任何开机自启 / 计划任务 / 服务
DisableProgramGroupPage=yes
CloseApplications=yes

[Languages]
Name: "chinese"; MessagesFile: "Languages\ChineseSimplified.isl"

[Types]
Name: "full"; Description: "完整安装"
Name: "compact"; Description: "紧凑安装（仅程序）"
Name: "custom"; Description: "自定义安装"; Flags: iscustom

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Excludes: "*.pdb"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "使用说明.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "更新日志.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSES.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\卸载 {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务："

[Run]
; 安装完成后启动应用。注意：不要加 skipifsilent —— 静默更新（自动更新）时也必须据此自动重启新版本。
Filename: "{app}\{#AppExe}"; Description: "立即启动 {#AppName}"; Flags: nowait postinstall

[UninstallDelete]
; 仅删除程序目录内容；用户数据目录 %APPDATA%\PcSecurityCenter 保留（隔离文件与报告不丢失）
Type: filesandordirs; Name: "{app}\runtimes"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
end;
