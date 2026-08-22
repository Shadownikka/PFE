; ═══════════════════════════════════════════════════════════════════
; NetMind — Inno Setup Installer Script
; Creates a professional Windows setup.exe with wizard UI
; ═══════════════════════════════════════════════════════════════════
; Compile with: iscc installer\netmind_setup.iss
; (Requires Inno Setup 6.x — https://jrsoftware.org/isdl.php)

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
LicenseFile=..\LICENSE
OutputDir=..\dist\installer
OutputBaseFilename=NetMind-Setup-{#MyAppVersion}
SetupIconFile=..\assets\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=120
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=NetMind — AI-Powered Network Management
VersionInfoProductName={#MyAppName}

; ── Visual branding ──────────────────────────────────────────────
WizardImageFile=..\assets\installer_banner.bmp
WizardSmallImageFile=..\assets\installer_icon.bmp

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checked
Name: "startatlogin"; Description: "Start NetMind when Windows starts"; GroupDescription: "Startup:"; Flags: unchecked
Name: "installnpcap"; Description: "Install Npcap (required for network scanning)"; GroupDescription: "Network Driver:"; Flags: checked

[Files]
; Main application (PyInstaller output)
Source: "..\dist\NetMind\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Npcap installer (bundled)
Source: "..\installer\npcap-installer.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: NpcapCheck

; Config template
Source: "..\installer\netmind_config.template"; DestDir: "{app}"; DestName: "config.ini"; Flags: onlyifdoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Comment: "Launch NetMind"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; Comment: "Launch NetMind"

[Registry]
; Auto-start on login (optional)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "NetMind"; ValueData: """{app}\{#MyAppExeName}"" --minimized"; Flags: uninsdeletevalue; Tasks: startatlogin

; Store install path for the tool to find config files
Root: HKLM; Subkey: "Software\NetMind"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\NetMind"; ValueType: string; ValueName: "Version"; ValueData: "{#MyAppVersion}"; Flags: uninsdeletekey

[Run]
; Install Npcap silently if selected
Filename: "{tmp}\npcap-installer.exe"; Parameters: "/S /winpcap_mode=yes"; StatusMsg: "Installing Npcap network driver..."; Tasks: installnpcap; Flags: waituntilterminated
; Launch after install
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runascurrentuser

[UninstallRun]
; Clean up config on uninstall
Filename: "cmd.exe"; Parameters: "/c rmdir /s /q ""{userappdata}\NetMind"""; Flags: runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{userappdata}\NetMind"

[Code]
// Check if Npcap is already installed
function NpcapCheck(): Boolean;
begin
  Result := not FileExists(ExpandConstant('{sys}\Npcap\NPFInstall.exe'));
end;

// Custom welcome page text
procedure InitializeWizard();
begin
  WizardForm.WelcomeLabel2.Caption :=
    'This will install NetMind {#MyAppVersion} on your computer.' + #13#10 + #13#10 +
    'NetMind is an AI-powered network management tool that monitors ' +
    'your network devices, manages bandwidth, and provides intelligent ' +
    'automation — all from a sleek desktop interface.' + #13#10 + #13#10 +
    'It is recommended that you close all other applications before continuing.';
end;

// Create AppData directory and initial config on install
procedure CurStepChanged(CurStep: TSetupStep);
var
  AppDataDir: String;
  ConfigFile: String;
begin
  if CurStep = ssPostInstall then
  begin
    AppDataDir := ExpandConstant('{userappdata}\NetMind');
    ForceDirectories(AppDataDir);

    // Create default config
    ConfigFile := AppDataDir + '\netmind_config.ini';
    if not FileExists(ConfigFile) then
    begin
      SaveStringToFile(ConfigFile,
        '# NetMind Configuration' + #13#10 +
        '[server]' + #13#10 +
        'url = https://netmind.io' + #13#10 +
        #13#10 +
        '[tool]' + #13#10 +
        'push_interval = 5' + #13#10 +
        'scan_interval = 30' + #13#10,
        False);
    end;
  end;
end;
