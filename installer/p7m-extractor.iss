; Inno Setup script for P7M Extractor.
; Compiled by CI with:  ISCC.exe /DAppVersion=vX.Y.Z installer\p7m-extractor.iss
; Expects the PyInstaller output in dist\p7m-extractor (repo root).

#ifndef AppVersion
  #define AppVersion "dev"
#endif

[Setup]
AppId={{9B7C1F2E-6D34-4A8B-9C55-2E7F0D1A6B93}
AppName=P7M Extractor
AppVersion={#AppVersion}
AppPublisher=Daniel Grasso
AppPublisherURL=https://github.com/daniel-g-carrasco/p7m-extractor
AppSupportURL=https://github.com/daniel-g-carrasco/p7m-extractor/issues
DefaultDirName={autopf}\P7M Extractor
DefaultGroupName=P7M Extractor
DisableProgramGroupPage=yes
; per-user install by default (no UAC); the dialog lets the user elevate
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputBaseFilename=p7m-extractor-setup-v{#AppVersion}-windows-x64
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\p7m-extractor.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ChangesAssociations=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "italian"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "assocp7m"; Description: "Apri i file .p7m con P7M Extractor (doppio clic per estrarre)"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; Flags: unchecked

[Files]
Source: "..\dist\p7m-extractor\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\P7M Extractor"; Filename: "{app}\p7m-extractor.exe"
Name: "{autodesktop}\P7M Extractor"; Filename: "{app}\p7m-extractor.exe"; Tasks: desktopicon

[Registry]
Root: HKA; Subkey: "Software\Classes\.p7m"; ValueType: string; ValueName: ""; ValueData: "P7MExtractor.p7m"; Flags: uninsdeletevalue; Tasks: assocp7m
Root: HKA; Subkey: "Software\Classes\.p7m\OpenWithProgids"; ValueType: string; ValueName: "P7MExtractor.p7m"; ValueData: ""; Flags: uninsdeletevalue; Tasks: assocp7m
Root: HKA; Subkey: "Software\Classes\P7MExtractor.p7m"; ValueType: string; ValueName: ""; ValueData: "Documento firmato digitalmente (P7M)"; Flags: uninsdeletekey; Tasks: assocp7m
Root: HKA; Subkey: "Software\Classes\P7MExtractor.p7m\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\p7m-extractor.exe,0"; Tasks: assocp7m
Root: HKA; Subkey: "Software\Classes\P7MExtractor.p7m\shell\open"; ValueType: string; ValueName: ""; ValueData: "Estrai con P7M Extractor"; Tasks: assocp7m
Root: HKA; Subkey: "Software\Classes\P7MExtractor.p7m\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\p7m-extractor.exe"" --gui ""%1"""; Tasks: assocp7m

[Run]
Filename: "{app}\p7m-extractor.exe"; Description: "{cm:LaunchProgram,P7M Extractor}"; Flags: nowait postinstall skipifsilent
