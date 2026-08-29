; NetMind — Inno Setup Installer Script
; Compile with: ISCC.exe installer\netmind_setup.iss

#define MyAppName "NetMind"
#define MyAppVersion "2.4.1"
#define MyAppPublisher "NetMind Technologies"
#define MyAppURL "https://netmind.io"
#define MyAppExeName "NetMind.exe"

[Setup]
AppId={{B5E8F2A1-7C3D-4E9F-A8B6-2D1C5F8E3A9B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/support
AppUpdatesURL={#MyAppURL}/updates
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\dist\installer
OutputBaseFilename=NetMind-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=120
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=NetMind AI-Powered Network Management
VersionInfoProductName={#MyAppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "startatlogin"; Description: "Start NetMind when Windows starts"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
Source: "..\dist\NetMind\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\installer\netmind_config.template"; DestDir: "{app}"; DestName: "config.ini"; Flags: onlyifdoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "NetMind"; ValueData: """{app}\{#MyAppExeName}"" --minimized"; Flags: uninsdeletevalue; Tasks: startatlogin
Root: HKCU; Subkey: "Software\NetMind"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\NetMind"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"; Flags: uninsdeletekey

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch NetMind"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallDelete]
Type: filesandordirs; Name: "{userappdata}\NetMind"

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  AppDataDir: String;
  ConfigFile: String;
  ConfigText: String;
begin
  if CurStep = ssPostInstall then
  begin
    AppDataDir := ExpandConstant('{userappdata}\NetMind');
    ForceDirectories(AppDataDir);

    ConfigFile := AppDataDir + '\netmind_config.ini';
    if not FileExists(ConfigFile) then
    begin
      ConfigText := '# NetMind Configuration' + #10 +
                    '[server]' + #10 +
                    'url = https://netmind.io' + #10 +
                    '[tool]' + #10 +
                    'push_interval = 5' + #10 +
                    'scan_interval = 30' + #10;
      SaveStringToFile(ConfigFile, ConfigText, False);
    end;
  end;
end;
