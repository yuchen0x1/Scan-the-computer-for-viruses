; 简体中文语言文件 —— Inno Setup 6 消息键名
; 说明：此前误用 Inno Setup 5 键名（BtnNext 等），Inno 6 已更名为 ButtonNext 等形式，
; 导致全部消息静默回退英文。此处按 Default.isl 的权威键名重新定义，并补齐全部消息键。

[LangOptions]
LanguageName=简体中文
LanguageID=$0804
LanguageCodePage=936
DialogFontSize=9

[Messages]

; *** 应用标题
SetupAppTitle=安装
SetupWindowTitle=安装 - %1
UninstallAppTitle=卸载
UninstallAppFullTitle=%1 卸载

; *** 通用标题
InformationTitle=信息
ConfirmTitle=确认
ErrorTitle=错误

; *** 向导页标题（仅限 Default.isl 已定义的键；导航按钮文字由 ButtonBack/ButtonNext 等提供）
WizardLicense=许可协议
WizardInfoBefore=安装前信息
WizardInfoAfter=安装后信息
WizardUserInfo=用户信息
WizardSelectDir=选择目标位置
WizardSelectComponents=选择组件
WizardSelectTasks=选择附加任务
WizardSelectProgramGroup=选择开始菜单文件夹
WizardReady=准备安装
WizardPreparing=正在准备安装
WizardInstalling=正在安装
WizardUninstalling=正在卸载
WizardPassword=密码

; *** 按钮
ButtonBack=< 上一步(&B)
ButtonNext=下一步(&N) >
ButtonInstall=安装(&I)
ButtonOK=确定
ButtonCancel=取消
ButtonYes=是(&Y)
ButtonYesToAll=全部是(&A)
ButtonNo=否(&N)
ButtonNoToAll=全部否(&O)
ButtonFinish=完成(&F)
ButtonBrowse=浏览(&B)...
ButtonWizardBrowse=浏览(&R)...
ButtonNewFolder=新建文件夹(&M)
ButtonStopDownload=停止下载(&S)
ButtonStopExtraction=停止解压(&S)

; *** 许可协议页（此前此处全部回退英文，且 RTF 未声明代码页导致中文乱码）
LicenseLabel=请仔细阅读以下许可协议，继续安装前必须接受协议条款。
; 许可页的 LicenseLabel3 与 LicenseLabel 会同时渲染，置空避免重复显示
LicenseLabel3=
LicenseAccepted=我接受协议(&A)
LicenseNotAccepted=我不接受协议(&D)

; *** 欢迎页
WelcomeLabel1=欢迎使用 [name] 安装向导
WelcomeLabel2=本向导将在您的计算机上安装 [name/ver]。%n%n建议在继续之前关闭所有其他应用程序。

; *** 安装前/后信息页
InfoBeforeLabel=请仔细阅读以下重要信息，再继续安装。
InfoBeforeClickLabel=准备好后，请点击"下一步"继续。
InfoAfterLabel=请仔细阅读以下重要信息。
InfoAfterClickLabel=准备好后，请点击"下一步"。

; *** 选择目标位置
SelectDirDesc=应把 [name] 安装到哪里？
SelectDirLabel3=安装向导将把 [name] 安装到下列文件夹。
SelectDirBrowseLabel=要安装到其他文件夹，请点击"浏览"。准备好后点击"下一步"。
DiskSpaceGBLabel=至少需要 [gb] GB 可用磁盘空间。
DiskSpaceMBLabel=至少需要 [mb] MB 可用磁盘空间。
PathLabel=路径(&P)：
SelectDirectoryLabel=请指定下一张磁盘的位置。

; *** 选择组件
SelectComponentsDesc=应安装哪些组件？
SelectComponentsLabel2=选择要安装的组件，取消选择不想安装的组件。准备好后点击"下一步"。
ComponentsDiskSpaceGBLabel=当前所选组件至少需要 [gb] GB 磁盘空间。
ComponentsDiskSpaceMBLabel=当前所选组件至少需要 [mb] MB 磁盘空间。
ComponentSize1=%1 KB
ComponentSize2=%1 MB
FullInstallation=完整安装
CompactInstallation=紧凑安装
CustomInstallation=自定义安装
NoUninstallWarningTitle=组件已存在
NoUninstallWarning=安装程序检测到您的计算机上已安装下列组件：%n%n%1%n%n取消选择这些组件不会卸载它们。%n%n是否仍要继续？

; *** 选择附加任务
SelectTasksLabel2=选择安装 [name] 时要执行的附加任务，然后点击"下一步"。
SelectTasksDesc=应执行哪些附加任务？

; *** 开始菜单文件夹
SelectStartMenuFolderDesc=安装程序应把程序快捷方式放在哪里？
SelectStartMenuFolderLabel3=安装程序将在下列开始菜单文件夹中创建程序快捷方式。
SelectStartMenuFolderBrowseLabel=要安装到其他文件夹，请点击"浏览"。准备好后点击"下一步"。
MustEnterGroupName=必须输入文件夹名称。
GroupNameTooLong=文件夹名称或路径过长。
InvalidGroupName=文件夹名称无效。
BadGroupName=文件夹名称不能包含下列任何字符：%n%n%1
NoProgramGroupCheck2=不创建开始菜单文件夹(&D)

; *** 准备安装
ReadyLabel1=安装向导已准备好在您的计算机上安装 [name]。
ReadyLabel2a=点击"安装"开始安装，或点击"上一步"复查、修改设置。
ReadyLabel2b=请检查下列设置，然后点击"安装"开始安装。
PreparingDesc=安装程序正在准备在您的计算机上安装 [name]。
ReadyMemoUserInfo=用户信息：
ReadyMemoDir=目标位置：
ReadyMemoType=安装类型：
ReadyMemoComponents=所选组件：
ReadyMemoGroup=开始菜单文件夹：
ReadyMemoTasks=附加任务：

; *** 用户信息
UserInfoDesc=请输入您的信息。
UserInfoName=用户名(&U)：
UserInfoNameRequired=必须输入用户名。
UserInfoOrg=组织(&O)：
UserInfoSerial=序列号(&S)：

; *** 密码
PasswordLabel1=本安装受密码保护。
PasswordLabel3=请输入密码，然后点击"下一步"继续。密码区分大小写。
PasswordEditLabel=密码(&P)：
IncorrectPassword=输入的密码不正确，请重试。

; *** 正在安装 / 完成
InstallingLabel=安装向导正在您的计算机上安装 [name]，请稍候…
FinishedHeadingLabel=正在完成 [name] 安装向导
FinishedLabelNoIcons=安装向导已完成在您的计算机上安装 [name]。
FinishedLabel=安装向导已完成在您的计算机上安装 [name]。您可以通过已安装的快捷方式运行该应用程序。
ClickFinish=点击"完成"退出安装向导。
ShowReadmeCheck=是，我要查看 README 文件

; *** 状态
ExtractingLabel=正在解压文件…
StatusExtractFiles=正在解压文件…
StatusDownloadFiles=正在下载文件…
StatusCreateDirs=正在创建目录…
StatusCreateIcons=正在创建快捷方式…
StatusCreateIniEntries=正在创建 INI 条目…
StatusCreateRegistryEntries=正在创建注册表项…
StatusRegisterFiles=正在注册文件…
StatusSavingUninstall=正在保存卸载信息…
StatusRunProgram=正在完成安装…
StatusRestartingApplications=正在重新启动应用程序…
StatusUninstalling=正在卸载 %1...
StatusRollback=正在回滚更改…
StatusClosingApplications=正在关闭应用程序…

; *** 下载与解压
DownloadingLabel2=正在下载文件…
StopDownload=确定要停止下载吗？
StopExtraction=确定要停止解压吗？
ArchiveIncorrectPassword=密码不正确
ArchiveIsCorrupted=压缩包已损坏
ArchiveUnsupportedFormat=不支持的压缩包格式

; *** 退出确认
ExitSetupTitle=退出安装向导
ExitSetupMessage=安装尚未完成。如果现在退出，程序将不会被安装。%n%n您可以稍后再次运行安装向导完成安装。%n%n是否退出安装向导？

; *** 卸载
ConfirmUninstall=确定要彻底移除 %1 及其所有组件吗？
UninstallStatusLabel=正在从您的计算机中移除 %1，请稍候…
UninstalledAll=已成功从您的计算机中移除 %1。
UninstalledMost=%1 卸载完成。%n%n部分组件无法自动移除，可手动删除。
UninstalledAndNeedsRestart=要完成 %1 的卸载，必须重新启动计算机。%n%n是否立即重启？
ConfirmDeleteSharedFileTitle=删除共享文件？
ConfirmDeleteSharedFile2=系统认为下列共享文件已不被任何程序使用。是否要让卸载程序删除该共享文件？%n%n如果仍有程序在使用该文件而它被删除，这些程序可能无法正常工作。如果不确定，请选择"否"。将该文件保留在系统中不会造成任何影响。
SharedFileNameLabel=文件名：
SharedFileLocationLabel=位置：

; *** 进程占用提示（CloseApplications=yes 时使用）
SetupAppRunningError=安装程序检测到 %1 正在运行。%n%n请先关闭它的所有实例，然后点击"确定"继续，或点击"取消"退出。
UninstallAppRunningError=卸载程序检测到 %1 正在运行。%n%n请先关闭它的所有实例，然后点击"确定"继续，或点击"取消"退出。
ApplicationsFound=以下应用程序正在使用安装程序需要更新的文件。建议允许安装程序自动关闭这些应用程序。
ApplicationsFound2=以下应用程序正在使用安装程序需要更新的文件。建议允许安装程序自动关闭这些应用程序。安装完成后，安装程序会尝试重新启动这些应用程序。
CloseApplications=自动关闭这些应用程序(&A)
DontCloseApplications=不要关闭这些应用程序(&D)

; *** 重启与关机
PrepareToInstallNeedsRestart=安装程序必须重新启动计算机。重启后请再次运行安装程序以完成 [name] 的安装。%n%n是否立即重启？
FinishedRestartLabel=要完成 [name] 的安装，安装程序必须重新启动计算机。是否立即重启？
FinishedRestartMessage=要完成 [name] 的安装，安装程序必须重新启动计算机。%n%n是否立即重启？
YesRadio=是，立即重启计算机(&Y)
NoRadio=否，稍后重启计算机(&N)
ShutdownBlockReasonInstallingApp=正在安装 %1。
ShutdownBlockReasonUninstallingApp=正在卸载 %1。

; *** 权限与提权
AdminPrivilegesRequired=安装本程序时必须由管理员登录。
PowerUserPrivilegesRequired=安装本程序时，必须以管理员或 Power Users 组成员身份登录。
OnlyAdminCanUninstall=只有具备管理员权限的用户才能卸载 %1。
PrivilegesRequiredOverrideTitle=选择安装模式
PrivilegesRequiredOverrideInstruction=选择安装模式
PrivilegesRequiredOverrideText1=%1 可以为所有用户安装（需要管理员权限），也可以仅为您安装。
PrivilegesRequiredOverrideText2=%1 可以仅为您安装，也可以为所有用户安装（需要管理员权限）。
PrivilegesRequiredOverrideAllUsers=为所有用户安装(&A)
PrivilegesRequiredOverrideAllUsersRecommended=为所有用户安装(&A)（推荐）
PrivilegesRequiredOverrideCurrentUser=仅为我安装(&M)
PrivilegesRequiredOverrideCurrentUserRecommended=仅为我安装(&M)（推荐）

; *** 磁盘与路径校验
CannotInstallToNetworkDrive=安装程序不能安装到网络驱动器。
CannotInstallToUNCPath=安装程序不能安装到 UNC 路径。
InvalidPath=必须输入带驱动器号的完整路径，例如：%n%nC:\APP%n%n或形如下列的 UNC 路径：%n%n\\server\share
InvalidDrive=所选驱动器或 UNC 共享不存在或不可访问，请选择其他位置。
DiskSpaceWarningTitle=磁盘空间不足
DiskSpaceWarning=安装至少需要 %1 KB 可用空间，但所选驱动器仅有 %2 KB 可用空间。%n%n是否仍要继续？
DirNameTooLong=文件夹名称或路径过长。
InvalidDirName=文件夹名称无效。
BadDirName32=文件夹名称不能包含下列任何字符：%n%n%1
DirExistsTitle=文件夹已存在
DirExists=文件夹：%n%n%1%n%n已存在。是否仍然安装到该文件夹？
DirDoesntExistTitle=文件夹不存在
DirDoesntExist=文件夹：%n%n%1%n%n不存在。是否创建该文件夹？

; *** 多磁盘安装
ChangeDiskTitle=安装程序需要下一张磁盘
SelectDiskLabel2=请插入磁盘 %1，然后点击"确定"。%n%n如果此磁盘中的文件位于下列文件夹之外的其他位置，请输入正确路径或点击"浏览"。
FileNotInDir2=在 "%2" 中找不到文件 "%1"。请插入正确的磁盘或选择其他文件夹。

; *** 语言选择
SelectLanguageTitle=选择安装语言
SelectLanguageLabel=选择安装过程中使用的语言。

; *** 错误对话框
LastErrorMessage=%1。%n%n错误 %2：%3
ErrorCreatingDir=安装程序无法创建目录 "%1"
ErrorTooManyFilesInDir=由于目录 "%1" 中的文件过多，无法在其中创建文件
ErrorInternal2=内部错误：%1
ErrorFunctionFailedNoCode=%1 失败
ErrorFunctionFailed=%1 失败；错误代码 %2
ErrorFunctionFailedWithMessage=%1 失败；错误代码 %2。%n%n%3
ErrorExecutingProgram=无法执行文件：%n%1
ErrorRegOpenKey=打开注册表项时出错：%n%1\%2
ErrorRegCreateKey=创建注册表项时出错：%n%1\%2
ErrorRegWriteKey=写入注册表项时出错：%n%1\%2
ErrorIniEntry=在文件 "%1" 中创建 INI 条目时出错。
ErrorRegisterServer=无法注册 DLL/OCX：%1
ErrorRegSvr32Failed=RegSvr32 失败，退出码为 %1
ErrorRegisterTypeLib=无法注册类型库：%1
ErrorOpeningReadme=尝试打开 README 文件时出错。
ErrorRestartingComputer=安装程序无法重新启动计算机，请手动重启。
ErrorChangingAttr=尝试更改现有文件属性时出错：
ErrorCreatingTemp=尝试在目标目录中创建文件时出错：
ErrorReadingSource=尝试读取源文件时出错：
ErrorCopying=尝试复制文件时出错：
ErrorDownloading=尝试下载文件时出错：
ErrorExtracting=尝试解压压缩包时出错：
ErrorReplacingExistingFile=尝试替换现有文件时出错：
ErrorRestartReplace=RestartReplace 失败：
ErrorRenamingTemp=尝试重命名目标目录中的文件时出错：
ErrorReadingExistingDest=尝试读取现有文件时出错：
ErrorCloseApplications=安装程序无法自动关闭所有应用程序。建议在继续之前手动关闭正在使用待更新文件的所有应用程序。
ErrorProgress=进度无效：%1 / %2
ErrorFileSize=文件大小无效：应为 %1，实际为 %2
ErrorDownloadAborted=下载已中止
ErrorDownloadFailed=下载失败：%1 %2
ErrorDownloadSizeFailed=获取文件大小失败：%1 %2
ErrorExtractionAborted=解压已中止
ErrorExtractionFailed=解压失败：%1
CannotContinue=安装程序无法继续。请点击"取消"退出。
SetupAborted=安装未完成。%n%n请修正问题后重新运行安装程序。

; *** 中止/重试/忽略
AbortRetryIgnoreSelectAction=选择操作
AbortRetryIgnoreRetry=重试(&R)
AbortRetryIgnoreIgnore=忽略错误并继续
AbortRetryIgnoreCancel=取消安装
RetryCancelSelectAction=选择操作
RetryCancelRetry=重试(&R)
RetryCancelCancel=取消
FileAbortRetryIgnoreSkipNotRecommended=跳过此文件（不推荐）(&S)
FileAbortRetryIgnoreIgnoreNotRecommended=忽略错误并继续（不推荐）(&I)

; *** 文件冲突
FileExistsSelectAction=选择操作
FileExists2=该文件已存在。
FileExistsOverwriteExisting=覆盖现有文件(&O)
FileExistsKeepExisting=保留现有文件(&K)
FileExistsOverwriteOrKeepAll=对后续冲突采用相同处理(&D)
ExistingFileNewerSelectAction=选择操作
ExistingFileNewer2=现有文件比安装程序尝试安装的文件更新。
ExistingFileNewerOverwriteExisting=覆盖现有文件(&O)
ExistingFileNewerKeepExisting=保留现有文件（推荐）(&K)
ExistingFileNewerOverwriteOrKeepAll=对后续冲突采用相同处理(&D)
ExistingFileReadOnly2=由于现有文件被标记为只读，无法替换它。
ExistingFileReadOnlyRetry=去除只读属性后重试(&R)
ExistingFileReadOnlyKeepExisting=保留现有文件(&K)

; *** 源文件校验
SourceIsCorrupted=源文件已损坏
SourceDoesntExist=源文件 "%1" 不存在
SourceVerificationFailed=源文件校验失败：%1
VerificationSignatureDoesntExist=签名文件 "%1" 不存在
VerificationSignatureInvalid=签名文件 "%1" 无效
VerificationKeyNotFound=签名文件 "%1" 使用了未知密钥
VerificationFileNameIncorrect=文件名称不正确
VerificationFileTagIncorrect=文件的标记不正确
VerificationFileSizeIncorrect=文件大小不正确
VerificationFileHashIncorrect=文件的哈希值不正确

; *** 运行与浏览
RunEntryExec=运行 %1
RunEntryShellExec=查看 %1
BrowseDialogTitle=浏览文件夹
BrowseDialogLabel=请在下面的列表中选择一个文件夹，然后点击"确定"。
NewFolderName=新建文件夹
ClickNext=点击"下一步"继续安装，或点击"取消"退出安装程序。
AboutSetupMenuItem=关于安装程序(&A)...
AboutSetupTitle=关于安装程序
AboutSetupMessage=%1 版本 %2%n%3%n%n%1 主页：%n%n%4
AboutSetupNote=
BeveledLabel=

; *** 平台与版本要求
WindowsVersionNotSupported=本程序不支持您的计算机运行的 Windows 版本。
WindowsServicePackRequired=本程序需要 %1 Service Pack %2 或更高版本。
NotOnThisPlatform=本程序不能在 %1 上运行。
OnlyOnThisPlatform=本程序必须在 %1 上运行。
OnlyOnTheseArchitectures=本程序只能安装到为下列处理器架构设计的 Windows 版本上：%n%n%1
WinVersionTooLowError=本程序需要 %1 版本 %2 或更高版本。
WinVersionTooHighError=本程序不能安装到 %1 版本 %2 或更高版本上。
UninstallOnlyOnWin64=此安装只能在 64 位 Windows 上卸载。

; *** 安装程序自身错误
SetupLdrStartupMessage=这将安装 %1。是否继续？
LdrCannotCreateTemp=无法创建临时文件，安装程序将中止。
LdrCannotExecTemp=无法在临时目录中执行文件，安装程序将中止。
SetupFileMissing=安装目录中缺少文件 %1。请修正问题，或重新获取本程序。
SetupFileCorrupt=安装文件已损坏，请重新获取本程序。
SetupFileCorruptOrWrongVer=安装文件已损坏，或与本版本安装程序不兼容。请修正问题或重新获取本程序。
InvalidParameter=命令行传入了无效参数：%n%n%1
SetupAlreadyRunning=安装程序已在运行。
PreviousInstallNotCompleted=上一个程序的安装/卸载未完成。您需要重启计算机才能完成该安装。%n%n重启计算机后，请再次运行安装程序以完成 [name] 的安装。

; *** 卸载记录错误
UninstallNotFound=文件 "%1" 不存在，无法卸载。
UninstallOpenError=无法打开文件 "%1"，无法卸载。
UninstallUnsupportedVer=卸载日志文件 "%1" 的格式不被本版本卸载程序识别，无法卸载。
UninstallUnknownEntry=卸载日志中遇到未知条目（%1）
UninstallDataCorrupted=文件 "%1" 已损坏，无法卸载。

; *** 卸载显示名标记
UninstallDisplayNameMark=%1（%2）
UninstallDisplayNameMarks=%1（%2、%3）
UninstallDisplayNameMark32Bit=32 位
UninstallDisplayNameMark64Bit=64 位
UninstallDisplayNameMarkAllUsers=所有用户
UninstallDisplayNameMarkCurrentUser=当前用户
