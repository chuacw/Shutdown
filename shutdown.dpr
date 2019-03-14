program shutdown;

{$APPTYPE CONSOLE}

uses
  Winapi.Windows,
  System.SysUtils,
  Winapi.Messages;

function SetCurrentPrivilege(const SystemName, Privilege: string; EnablePrivilege: Bool): Bool;
var
  LToken: THandle;
  luid: TLargeInteger;
  tp, tpPrevious: TOKEN_PRIVILEGES;
  PreviousSize: DWORD;
  LSystemName: PChar;
begin
  Result := False;
  if SystemName = '' then
    LSystemName := nil else
    LSystemName := PChar(SystemName);
  if LookupPrivilegeValue(LSystemName, PChar(Privilege), luid) and
    OpenProcessToken(GetCurrentProcess, TOKEN_QUERY or TOKEN_ADJUST_PRIVILEGES, LToken) then
    begin
      tp.PrivilegeCount := 1;
      tp.Privileges[0].Luid := luid;
      tp.Privileges[0].Attributes := 0;
      AdjustTokenPrivileges(LToken, False, tp, SizeOf(tpPrevious),
                           tpPrevious, PreviousSize);
      if GetLastError = ERROR_SUCCESS then
        begin
          tpPrevious.PrivilegeCount := 1;
          tpPrevious.Privileges[0].Luid := luid;
          if EnablePrivilege then
            tpPrevious.Privileges[0].Attributes :=
             tpPrevious.Privileges[0].Attributes or SE_PRIVILEGE_ENABLED
          else
            tpPrevious.Privileges[0].Attributes :=
             tpPrevious.Privileges[0].Attributes and not SE_PRIVILEGE_ENABLED;
          AdjustTokenPrivileges(LToken, False, tpPrevious, SizeOf(tpPrevious),
                               nil, PreviousSize);
          Result := GetLastError = ERROR_SUCCESS;
        end;
      CloseHandle(LToken);
    end;
end;

function GetComputerName: string;
var
  LBuffer: array[0..MAX_COMPUTERNAME_LENGTH] of Char;
  LSize: DWORD;
begin
  LSize := MAX_COMPUTERNAME_LENGTH;
  if Winapi.Windows.GetComputerName(LBuffer, LSize) then
    begin
      SetString(Result, LBuffer, LSize);
    end else
    begin
      Result := '';
    end;
end;

function NameIsLocal(const AMachineName: string): Boolean;
var
  LSystemName, LMachineName: string;
  I: Integer;
begin
  if (AMachineName = '') or (CompareText(AMachineName, 'LOCAL') = 0) then
    Exit(True);
  I := Pos('\\', AMachineName);
  if I>0 then
    LMachineName := Copy(AMachineName, 3, Length(AMachineName)) else
    LMachineName := AMachineName;
  LSystemName := GetComputerName;
  Result := CompareText(LMachineName, LSystemName) = 0;
end;


const
  SuccessStr: array[Boolean] of string=('Fail', 'Succeed');
  SE_REMOTE_SHUTDOWN_NAME = 'SeRemoteShutdownPrivilege';
  SE_SHUTDOWN_NAME = 'SeShutdownPrivilege';
var
  LReboot, LForced: Bool;
  LMessage, LMachineName: string;
  LTimeout: DWORD;
  LParam, LUserPassword, LUserName: string;
  LIsMachineLocal, AbortShutdown, Connected: Boolean;
  LNetResource: TNetResource;
  LAbortStatus, LShutdownStatus: Boolean;
  I, LParamCount: Integer;
  LShutdownPrivilege: string;
begin
  WriteLn('Remote Shutdown v1.00 by chuacw (c) 2001');

  WriteLn('Usage: shutdown [params] MACHINENAME');
  WriteLn('  -a (abort current shutdown)');
  WriteLn('  -f (force apps to close on shutdown)');
  WriteLn('  -m "Message"');
  WriteLn('  -r (reboot after shutdown)');
  WriteLn('  -u username');
  WriteLn('  -p password ');
  WriteLn('  -t timeout (timeout in seconds)');
  WriteLn;
  WriteLn('MACHINENAME: LOCAL or \\hostname');
  WriteLn('  if MACHINENAME is empty, it implies the local machine');

  WriteLn;

  LTimeout := 600; // Default timeout of 600s
  LForced := False; // Don't force the machine to shutdown without
                  // considering whether to save documents... ;o)
  LReboot := False; // Don't reboot after machine shutdown
  LMessage := EmptyStr;
  LUserPassword := EmptyStr;
  LUserName := EmptyStr;
  AbortShutdown := False;
  if ParamCount>=1 then
    begin
      I := 1; LParamCount := ParamCount;
      while I <= LParamCount do
        begin
          LParam := ParamStr(I);
          if (Length(LParam) >= 2) and ((LParam[1]='-') or (LParam[1]='/')) then
            begin
              case UpCase(LParam[2]) of
                'A': begin // abort
                  AbortShutdown := True;
                  Inc(I);
                end;
                'F': begin
                  LForced := True;
                  Inc(I);
                end;
                'M': begin
                  LMessage := ParamStr(I+1);
                  Inc(I, 2);
                end;
                'P': begin
                  LParam := ParamStr(I+1);
                  LUserPassword := LParam;
                  Inc(I, 2);
                end;
                'R': begin
                  LReboot := True;
                  Inc(I);
                end;
                'T': begin
                  LParam := ParamStr(I+1);
                  LTimeout := StrToIntDef(LParam, 600);
                  Inc(I, 2);
                end;
                'U': begin
                  LParam := ParamStr(I+1);
                  LUserName := LParam;
                  Inc(I, 2);
                end;
              else
                LMachineName := LParam;
                Inc(I);
              end;
            end else
            begin
              LMachineName := LParam;
              Inc(I);
            end;
        end;

      LIsMachineLocal := NameIsLocal(LMachineName);

      if LIsMachineLocal then
        begin
          LMachineName := EmptyStr;
          LShutdownPrivilege := SE_SHUTDOWN_NAME;
        end else
        begin
          Write(Format('Connecting to %s...: ', [LMachineName]));
          LNetResource.dwType := RESOURCETYPE_ANY;
          LNetResource.lpRemoteName := PChar(LMachineName);
          LNetResource.lpLocalName := nil;
          LNetResource.lpProvider := nil;
          Connected := WNetAddConnection2(LNetResource, PChar(LUserPassword), PChar(LUserName), 0) = NO_ERROR;
          WriteLn(Format('%sed', [SuccessStr[Connected]]));
          LShutdownPrivilege := SE_REMOTE_SHUTDOWN_NAME;
        end;

      if not SetCurrentPrivilege(LMachineName, LShutdownPrivilege, True) then
        WriteLn('Unable to obtain shutdown privilege due to: ', SysErrorMessage(GetLastError));

      if AbortShutdown then
        begin
          Write('Abort shutdown: ');
             LAbortStatus := AbortSystemShutdown(PChar(LMachineName));
          if LAbortStatus then
            begin
              WriteLn(Format('%sed.', [SuccessStr[LAbortStatus]]));
            end else
            begin
              Write(SuccessStr[LAbortStatus], 'ed. ');
              WriteLn(SysErrorMessage(GetLastError));
            end;
        end else
        begin
          Write(Format('Shutting down machine %s...: ', [LMachineName]));
          LShutdownStatus := InitiateSystemShutdown(PChar(LMachineName), PChar(LMessage), LTimeout, LForced, LReboot);
          if LShutdownStatus then
            begin
              WriteLn(Format('%sed.', [SuccessStr[LShutdownStatus]]));
            end else
            begin
              Write(SuccessStr[LShutdownStatus], 'ed. ');
              WriteLn(SysErrorMessage(GetLastError));
            end;
        end;

      SetCurrentPrivilege(LMachineName, LShutdownPrivilege, False);
      if not LIsMachineLocal then
        begin
          Write(Format('Disconnecting from %s...: ', [LMachineName]));
          WriteLn(Format('%sed', [SuccessStr[WNetCancelConnection2(LNetResource.lpRemoteName, 0, True)=NO_ERROR]]));
        end;

      if DebugHook <> 0 then
        ReadLn;
    end;
end.
