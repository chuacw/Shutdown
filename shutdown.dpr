program shutdown;
{$APPTYPE CONSOLE}

uses
  Winapi.Windows,
  System.SysUtils,
  Winapi.Messages,
  Winapi.PrivilegeConsts in 'Winapi.PrivilegeConsts.pas';

function SetCurrentPrivilege(const SystemName, Privilege: string;
  EnablePrivilege: LongBool): LongBool;
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

///<summary>Checks if AMachineName refers to the local machine and returns true if so.</summary>
///<param name="AMachineName">Name to check</param>
function NameIsLocal(const AMachineName: string): LongBool;
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

procedure ShowHelp;
begin
  WriteLn('Usage: shutdown [params] MACHINENAME');
  WriteLn('  -a (abort current shutdown)');
  WriteLn('  -f (force apps to close on shutdown)');
  WriteLn('  -?,h (Show help)');
  WriteLn('  -m "Message"');
  WriteLn('  -r (reboot after shutdown)');
  WriteLn('  -u username');
  WriteLn('  -p password ');
  WriteLn('  -t timeout (timeout in seconds)');
  WriteLn;
  WriteLn('MACHINENAME: LOCAL or \\remotehostname');
  WriteLn('  if MACHINENAME is empty or LOCAL, it implies the local machine');

  WriteLn;
end;

///<summary>Shuts down the designated machine, or aborts a shutdown.</summary>
///<param name="AMachineName">The machine to shutdown, or abort shutdown.</param>
///<param name="AUserName">Username to connect to the machine.</param>
///<param name="APassword">Password to use to connect to the machine</param>
///<param name="AMessage">Message to display when shutting down.</param>
///<param name="ATimeout">Amount of time in seconds to wait before shutting down.</param>
///<param name="AAbortShutdown">If true, aborts the shutdown on the designated machine.</param>
///<param name="AForce">If true, force apps to close on shutdown.</param>
///<param name="AReboot">If true, reboots after shutdown is completed.</param>
procedure ShutdownProc(const AMachineName, AUserName, APassword, AMessage: string;
  ATimeout: DWORD; AAbortShutdown, AForce, AReboot: LongBool);
const
  SuccessStr: array[Boolean] of string=('Fail', 'Succeed');
var
  LConnected, LIsMachineLocal: LongBool;
  LMachineName, LShutdownPrivilege: string;
  LNetResource: TNetResource;
  LAbortStatus, LShutdownStatus: LongBool;
begin
  LMachineName := AMachineName;
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
      LConnected := WNetAddConnection2(LNetResource, PChar(APassword),
        PChar(AUserName), CONNECT_INTERACTIVE) = NO_ERROR;
      WriteLn(Format('%sed.', [SuccessStr[LConnected]]));
      if not LConnected then
        begin
          WriteLn(SysErrorMessage(GetLastError));
          Exit;
        end;
      LShutdownPrivilege := SE_REMOTE_SHUTDOWN_NAME;
    end;

  if not SetCurrentPrivilege(LMachineName, LShutdownPrivilege, True) then
    WriteLn('Unable to obtain shutdown privilege due to: ', SysErrorMessage(GetLastError));

  if AAbortShutdown then
    begin
      Write('Abort shutdown: ');
      LAbortStatus := AbortSystemShutdown(PChar(LMachineName));
      if LAbortStatus then
        begin
          WriteLn(Format('%sed.', [SuccessStr[LAbortStatus]]));
        end else
        begin
          Write(SuccessStr[LAbortStatus], 'ed. ');
          WriteLn(SysErrorMessage(GetLastError), '.');
        end;
    end else
    begin
      Write(Format('Shutting down machine %s...: ', [LMachineName]));
      LShutdownStatus := InitiateSystemShutdown(PChar(LMachineName),
        PChar(AMessage), ATimeout, AForce, AReboot);
      if LShutdownStatus then
        begin
          WriteLn(Format('%sed.', [SuccessStr[LShutdownStatus]]));
        end else
        begin
          Write(SuccessStr[LShutdownStatus], 'ed. ');
          WriteLn(SysErrorMessage(GetLastError), '.');
        end;
    end;

  SetCurrentPrivilege(LMachineName, LShutdownPrivilege, False);
  if not LIsMachineLocal then
    begin
      Write(Format('Disconnecting from %s...: ', [LMachineName]));
      WriteLn(Format('%sed', [
        SuccessStr[WNetCancelConnection2(LNetResource.lpRemoteName, 0,
          True)=NO_ERROR]]));
    end;
end;

function ParseCmdLine(var OMachineName, OUserName, OPassword, OMessage: string;
  var OTimeout: DWORD; var OAbortShutdown, OForced, OReboot: LongBool): LongBool;
var
  I, LParamCount: Integer;
  LParam: string;
begin
  Result := ParamCount>=1;
  if Result then
    begin
      I := 1; LParamCount := ParamCount;
      while I <= LParamCount do
        begin
          LParam := ParamStr(I);
          if (Length(LParam) >= 2) and ((LParam[1] = '-') or (LParam[1] = '/')) then
            begin
              case UpCase(LParam[2]) of
                '?', 'H': begin
                  ShowHelp;
                  Exit(False);
                end;
                'A': begin // abort
                  OAbortShutdown := True;
                  Inc(I);
                end;
                'F': begin
                  OForced := True;
                  Inc(I);
                end;
                'M': begin
                  OMessage := ParamStr(I+1);
                  Inc(I, 2);
                end;
                'P': begin
                  LParam := ParamStr(I+1);
                  OPassword := LParam;
                  Inc(I, 2);
                end;
                'R': begin
                  OReboot := True;
                  Inc(I);
                end;
                'T': begin
                  LParam := ParamStr(I+1);
                  OTimeout := StrToIntDef(LParam, 600);
                  if (OTimeout <> 0) and (OMessage = '') then
                    OMessage := Format('Shutting down in %d secs.', [OTimeout]);
                  Inc(I, 2);
                end;
                'U': begin
                  LParam := ParamStr(I+1);
                  OUserName := LParam;
                  Inc(I, 2);
                end;
              else
                OMachineName := LParam;
                Inc(I);
              end;
            end else
            begin
              OMachineName := LParam;
              Inc(I);
            end;
        end;
    end;
end;

procedure MainApp;
var
  LAbortShutdown, LReboot, LForced: LongBool;
  LMessage, LMachineName, LUserPassword, LUserName: string;
  LTimeout: DWORD;
begin
  WriteLn('Remote Shutdown v1.10 by chuacw (c) 2001, 2019');
  WriteLn;

  LTimeout := 600; // Default timeout of 600s
  LForced := False; // Don't force the machine to shutdown without
                  // considering whether to save documents... ;o)
  LReboot := False; // Don't reboot after machine shutdown
  LMessage := EmptyStr;
  LUserPassword := EmptyStr;
  LUserName := EmptyStr;
  LAbortShutdown := False;

  if ParamCount = 0 then
    Exit;

  if ParseCmdLine(LMachineName, LUserName, LUserPassword, LMessage, LTimeout,
    LAbortShutdown, LForced, LReboot) then
    begin
      ShutdownProc(LMachineName, LUserName, LUserPassword, LMessage, LTimeout,
        LAbortShutdown, LForced, LReboot);
{$WARN SYMBOL_PLATFORM OFF}
      if DebugHook <> 0 then
        ReadLn;
    end;
end;

// Independent test
procedure Test;
var
  MachineName, UserName, Password: string;
begin
  UserName := ''; // ...
  Password := ''; // ...
  MachineName := '\\....'; // IP address or hostname
  ShutdownProc(MachineName, UserName, Password, 'Shutting down in 10s',
    10, False, True, False);
end;

begin
  MainApp;
end.
