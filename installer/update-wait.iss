{ Waiting in Setup preserves the hand-off from clients already in the field.
  The app can exit before GLib's session broker frees the bundled DLLs. }
const
  SYNCHRONIZE = $00100000;
  WAIT_OBJECT_0 = 0;
  GENERIC_READ_WRITE = $C0000000;
  OPEN_EXISTING = 3;
  ERROR_FILE_NOT_FOUND = 2;
  ERROR_PATH_NOT_FOUND = 3;
  ERROR_ACCESS_DENIED = 5;
  ERROR_SHARING_VIOLATION = 32;
  ERROR_INVALID_PARAMETER = 87;

{ The Windows loader supplies the .dll extension for system module names. }
function OpenProcess(Access: DWORD; Inherit: BOOL; PID: DWORD): THandle;
  external 'OpenProcess@kernel32 stdcall';
function WaitForSingleObject(Handle: THandle; Milliseconds: DWORD): DWORD;
  external 'WaitForSingleObject@kernel32 stdcall';
function CloseHandle(Handle: THandle): BOOL;
  external 'CloseHandle@kernel32 stdcall';
function CreateFileW(Name: String; Access, Share: DWORD; Security: LongWord;
  Disposition, Flags: DWORD; Template: THandle): THandle;
  external 'CreateFileW@kernel32 stdcall';

function WaitForUpdateProcess(PID: Integer): Boolean;
var
  Handle: THandle;
  Error: LongInt;
begin
  Result := PID = 0;
  if Result then
    Exit;
  Handle := OpenProcess(SYNCHRONIZE, False, PID);
  if Handle = 0 then begin
    Error := DLLGetLastError;
    Log(Format('Opening update PID %d returned %d', [PID, Error]));
    Result := Error = ERROR_INVALID_PARAMETER; { already exited }
    Exit;
  end;
  try
    Result := WaitForSingleObject(Handle, 20000) = WAIT_OBJECT_0;
  finally
    CloseHandle(Handle);
  end;
  Log(Format('Update PID %d exited: %d', [PID, Ord(Result)]));
end;

function UpdateFileError(Name: String): LongInt;
var
  Handle: THandle;
begin
  { An exclusive read alone can succeed while an executable image is mapped. }
  Handle := CreateFileW(Name, GENERIC_READ_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
  if Handle = THandle(-1) then begin
    Result := DLLGetLastError;
    if (Result = ERROR_FILE_NOT_FOUND) or (Result = ERROR_PATH_NOT_FOUND) then
      Result := 0;
  end else begin
    CloseHandle(Handle);
    Result := 0;
  end;
end;

function WaitForUpdateFiles(AppDir, PID: String): Boolean;
var
  Files: array of String;
  Blocked: String;
  Attempt, I, Error: Integer;
begin
  Log('Waiting for update files');
  Result := False;
  if not WaitForUpdateProcess(StrToIntDef(PID, 0)) then
    Exit;
  SetArrayLength(Files, 3);
  Files[0] := AppDir + '\p7m-extractor.exe';
  Files[1] := AppDir + '\_internal\gdbus.exe';
  Files[2] := AppDir + '\_internal\libgio-2.0-0.dll';
  Blocked := '';
  for Attempt := 0 to 150 do begin
    Error := 0;
    for I := 0 to GetArrayLength(Files) - 1 do begin
      Error := UpdateFileError(Files[I]);
      if Error <> 0 then
        Break;
    end;
    if Error = 0 then begin
      Log('Update files are writable');
      Result := True;
      Exit;
    end;
    if Blocked <> Files[I] then begin
      Blocked := Files[I];
      Log(Format('Update file busy: %s (Windows error %d)', [Blocked, Error]));
    end;
    if (Error <> ERROR_ACCESS_DENIED) and (Error <> ERROR_SHARING_VIOLATION) then
      Break;
    if Attempt < 150 then
      Sleep(100);
  end;
  Log('Update files did not become writable: ' + Blocked);
end;
