; NetMind Windows Installer — Inno Setup 6 Script
; Build: iscc NetMind.iss
; Output: NetMindSetup.exe

#define AppName      "NetMind"
#define AppVersion   "1.0.0"
#define AppPublisher "NetMind"
#define AppURL       "https://github.com/your-repo/NetMind"
#define AppExeName   "NetMind.exe"

[Setup]
AppId={A3F2C1B4-7E8D-4F5A-9C2B-1D3E6F8A0B4C}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisherURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
OutputDir=installer
OutputBaseFilename=NetMindSetup-{#AppVersion}
; Compression
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
; Privilege — needs admin for raw sockets and network tools
PrivilegesRequired=admin
; Icon — uncomment when logo.ico is provided
; SetupIconFile=logo.ico
UninstallDisplayIcon={app}\{#AppExeName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Minimum Windows 10
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"
Name: "startupicon"; Description: "Launch NetMind on &Windows startup"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
; Main application files (output from PyInstaller)
Source: "dist\NetMind\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Ollama installer (bundled — download from https://ollama.com/download/OllamaSetup.exe)
; Source: "tools\OllamaSetup.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

; Npcap installer (for packet capture on Windows)
; Source: "tools\npcap-installer.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: startupicon

[Run]
; Install Npcap if bundled (required for packet capture on Windows)
; Filename: "{tmp}\npcap-installer.exe"; Parameters: "/S"; StatusMsg: "Installing Npcap (packet capture driver)..."; Flags: waituntilterminated runascurrentuser

; Install Ollama if bundled
; Filename: "{tmp}\OllamaSetup.exe"; Parameters: "/S"; StatusMsg: "Installing Ollama (local AI engine)..."; Flags: waituntilterminated runascurrentuser

; Pull Llama 3.2 model after install
Filename: "ollama"; Parameters: "pull llama3.2"; StatusMsg: "Downloading Llama 3.2 AI model (~2GB)..."; Flags: waituntilterminated runhidden; Check: OllamaInstalled

; Launch after install
Filename: "{app}\{#AppExeName}"; Description: "Launch NetMind"; Flags: nowait postinstall skipifsilent

[Code]
function OllamaInstalled(): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec('ollama', '--version', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

procedure InitializeWizard();
begin
  WizardForm.WelcomeLabel2.Caption :=
    'NetMind is an AI-powered bandwidth management tool that uses Llama 3.2 (running locally) ' +
    'to automatically manage your network based on your business needs.' + #13#10 + #13#10 +
    'Requirements:' + #13#10 +
    '  • Windows 10/11 (64-bit)' + #13#10 +
    '  • Ollama installed (for local AI)' + #13#10 +
    '  • Npcap installed (for packet capture)' + #13#10 +
    '  • ~6 GB RAM recommended' + #13#10 + #13#10 +
    'NOTE: Full network management features (ARP spoofing, rate limiting) ' +
    'require WSL2 on Windows. AI features work natively on Windows.';
end;
