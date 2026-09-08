; Inno Setup script for P7M Extractor.
; Compiled by CI with:  ISCC.exe /DAppVersion=X.Y.Z installer\p7m-extractor.iss
; Expects the PyInstaller output in dist\p7m-extractor (repo root).
;
; The registry layout below mirrors win_register() in p7m_extractor.py
; (ProgID P7MExtractor.p7m, verb P7MExtractor.extract): keep them in sync.

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
AppUpdatesURL=https://github.com/daniel-g-carrasco/p7m-extractor/releases
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
; upgrades: close the running app instead of failing on files in use
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "italian"; MessagesFile: "compiler:Languages\Italian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "assocp7m"; Description: "Apri i file .p7m con P7M Extractor (doppio clic per estrarre)"
Name: "contextmenu"; Description: "Aggiungi «Estrai il contenuto con P7M Extractor» al menu contestuale dei file .p7m"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; Flags: unchecked

[Files]
Source: "..\dist\p7m-extractor\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\P7M Extractor"; Filename: "{app}\p7m-extractor.exe"
Name: "{autodesktop}\P7M Extractor"; Filename: "{app}\p7m-extractor.exe"; Tasks: desktopicon

[Registry]
; --- ProgID: what a .p7m is and how to open it (always written, so the app
;     shows up in "Open with" even when the association task is unchecked)
Root: HKA; Subkey: "Software\Classes\P7MExtractor.p7m"; ValueType: string; ValueName: ""; ValueData: "Documento firmato digitalmente (P7M)"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\P7MExtractor.p7m\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\p7m-extractor.exe,0"
Root: HKA; Subkey: "Software\Classes\P7MExtractor.p7m\shell\open"; ValueType: string; ValueName: ""; ValueData: "Estrai con P7M Extractor"
Root: HKA; Subkey: "Software\Classes\P7MExtractor.p7m\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\p7m-extractor.exe"" --gui ""%1"""
Root: HKA; Subkey: "Software\Classes\.p7m\OpenWithProgids"; ValueType: string; ValueName: "P7MExtractor.p7m"; ValueData: ""; Flags: uninsdeletevalue
; --- default handler for .p7m (task)
Root: HKA; Subkey: "Software\Classes\.p7m"; ValueType: string; ValueName: ""; ValueData: "P7MExtractor.p7m"; Flags: uninsdeletevalue; Tasks: assocp7m
; --- context-menu verb on every .p7m, whatever the default app is (task).
;     MultiSelectModel=Player: Explorer runs it for each selected file with
;     no "too many files" prompt; the app merges them into its single window.
Root: HKA; Subkey: "Software\Classes\SystemFileAssociations\.p7m\shell\P7MExtractor.extract"; ValueType: string; ValueName: ""; ValueData: "Estrai il contenuto con P7M Extractor"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\SystemFileAssociations\.p7m\shell\P7MExtractor.extract"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\p7m-extractor.exe,0"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\SystemFileAssociations\.p7m\shell\P7MExtractor.extract"; ValueType: string; ValueName: "MultiSelectModel"; ValueData: "Player"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\SystemFileAssociations\.p7m\shell\P7MExtractor.extract\command"; ValueType: string; ValueName: ""; ValueData: """{app}\p7m-extractor.exe"" --gui ""%1"""; Tasks: contextmenu
; --- "Open with" friendly name when the exe itself is picked
Root: HKA; Subkey: "Software\Classes\Applications\p7m-extractor.exe"; ValueType: string; ValueName: "FriendlyAppName"; ValueData: "P7M Extractor"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\Applications\p7m-extractor.exe\SupportedTypes"; ValueType: string; ValueName: ".p7m"; ValueData: ""
Root: HKA; Subkey: "Software\Classes\Applications\p7m-extractor.exe\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\p7m-extractor.exe"" --gui ""%1"""
; --- Default Programs registration: lists the app in Settings > Default apps
;     and makes the ms-settings deep link used by the app work
Root: HKA; Subkey: "Software\P7M Extractor\Capabilities"; ValueType: string; ValueName: "ApplicationName"; ValueData: "P7M Extractor"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\P7M Extractor\Capabilities"; ValueType: string; ValueName: "ApplicationDescription"; ValueData: "Estrae il documento originale dai file firmati .p7m"
Root: HKA; Subkey: "Software\P7M Extractor\Capabilities\FileAssociations"; ValueType: string; ValueName: ".p7m"; ValueData: "P7MExtractor.p7m"
Root: HKA; Subkey: "Software\RegisteredApplications"; ValueType: string; ValueName: "P7M Extractor"; ValueData: "Software\P7M Extractor\Capabilities"; Flags: uninsdeletevalue

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\p7m-extractor"

[UninstallRun]
; the app may have registered itself per-user from its Preferences: clean that up too
Filename: "{app}\p7m-extractor.exe"; Parameters: "--unregister"; RunOnceId: "UnregisterShell"; Flags: runhidden

[Run]
Filename: "{app}\p7m-extractor.exe"; Description: "{cm:LaunchProgram,P7M Extractor}"; Flags: nowait postinstall skipifsilent
