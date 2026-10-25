; EgressScope per-user installer (no administrator rights required).
; Build with Inno Setup 6.0+; this installer targets x64 Windows only.
;
; Environment / preprocessor overrides:
;   EGRESS_SCOPE_VERSION      numeric X.Y.Z version, e.g. 0.4.0 (fallback: 0.0.0-dev)
;   EGRESS_SCOPE_EXE          path to the packaged EgressScope.exe
;   EGRESS_SCOPE_OUTPUT_DIR   setup output directory
; The release workflow sets all three explicitly.

#ifndef MyAppVersion
  #define MyAppVersion GetEnv("EGRESS_SCOPE_VERSION")
#endif
#if MyAppVersion == ""
  #define MyAppVersion "0.0.0-dev"
#endif

#ifndef MySourceExe
  #define MySourceExe GetEnv("EGRESS_SCOPE_EXE")
#endif
#if MySourceExe == ""
  #define MySourceExe "..\dist\EgressScope.exe"
#endif

#ifndef MyOutputDir
  #define MyOutputDir GetEnv("EGRESS_SCOPE_OUTPUT_DIR")
#endif
#if MyOutputDir == ""
  #define MyOutputDir "..\release"
#endif

#define MyAppName "EgressScope"
#define MyAppPublisher "EgressScope"
#define MyProjectUrl "https://github.com/1wu-davy-2/EgressScope"

[Setup]
AppId={{9F4C2D7A-6B31-4D8E-9A2F-3C5E7B1D8A40}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyProjectUrl}
AppSupportURL={#MyProjectUrl}/issues
AppUpdatesURL={#MyProjectUrl}/releases
DefaultDirName={localappdata}\Programs\EgressScope
DefaultGroupName={#MyAppName}
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir={#MyOutputDir}
OutputBaseFilename=EgressScope-Setup-v{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\EgressScope.exe
SetupIconFile=..\web\assets\favicon.ico
LicenseFile=..\LICENSE
InfoBeforeFile=UNSIGNED-NOTE.txt
CloseApplications=yes
RestartApplications=no
AllowNoIcons=yes
UsePreviousAppDir=no
MinVersion=10.0

[Files]
Source: "{#MySourceExe}"; DestDir: "{app}"; DestName: "EgressScope.exe"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务："; Flags: unchecked

[Icons]
Name: "{group}\EgressScope"; Filename: "{app}\EgressScope.exe"; WorkingDir: "{app}"; IconFilename: "{app}\EgressScope.exe"
Name: "{group}\恢复系统代理"; Filename: "{app}\EgressScope.exe"; Parameters: "--restore-proxy"; WorkingDir: "{app}"; IconFilename: "{app}\EgressScope.exe"
Name: "{autodesktop}\EgressScope"; Filename: "{app}\EgressScope.exe"; WorkingDir: "{app}"; Tasks: desktopicon; IconFilename: "{app}\EgressScope.exe"

[Run]
; Normal (interactive) install: launch once so the per-user Run key is registered.
Filename: "{app}\EgressScope.exe"; Description: "启动 EgressScope"; Flags: nowait postinstall skipifsilent
; Silent update/install: restart the app after the installer replaced the files.
Filename: "{app}\EgressScope.exe"; Flags: nowait; Check: WizardSilent

[UninstallRun]
Filename: "{app}\EgressScope.exe"; Parameters: "--disable-autostart --headless"; Flags: runhidden waituntilterminated; RunOnceId: "DisableAutostart"
Filename: "{app}\EgressScope.exe"; Parameters: "--restore-proxy --headless"; Flags: runhidden waituntilterminated; RunOnceId: "RestoreProxy"

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep <> usPostUninstall then
    Exit;
  DataDir := ExpandConstant('{localappdata}\EgressScope');
  if not DirExists(DataDir) then
    Exit;
  // Silent uninstall keeps audit data. Deleting evidence must be an explicit,
  // interactive choice because the directory also holds exported evidence.
  if UninstallSilent then
    Exit;
  if MsgBox(
    '是否同时删除 EgressScope 的审计数据库、配置、证书、日志与已导出的证据文件？' + #13#10 +
    DataDir + #13#10#13#10 +
    '选择“否”会保留这些数据，便于重新安装后继续使用。此操作不可恢复。',
    mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
    DelTree(DataDir, True, True, True);
end;
