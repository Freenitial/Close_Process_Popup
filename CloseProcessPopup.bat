
<# ::
    @echo off & setlocal
    set "CPPversion=1.1"
    title Close Processes Popup v%CPPversion% Launcher

    for %%A in ("/?" "-?" "--?" "/help" "-help" "--help") do if /I "%~1"=="%%~A" goto :help
    
    if exist %SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe   set "powershell=%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe"
    if exist %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe  set "powershell=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"

    set args=%*
    if defined args set "args=%args:"=\"%"
    
    :: PowerShell self-read, skipping batch part
    %powershell% -NoLogo -NoProfile -Ex Bypass -Command ^
        "$sb=[ScriptBlock]::Create([IO.File]::ReadAllText('%~f0'));& $sb @args" %args%

    exit /b %errorlevel% 

    :help
    echo.
    echo.
    echo    =============================================================================
    echo                              Close Processes Popup v%CPPversion%
    echo                                          ---
    echo                       Author : Leo Gillet / Freenitial on GitHub
    echo    =============================================================================
    echo.
    echo.
    echo    PARAMETERS:
    echo       ------------
    echo       -Process (string list)
    echo          Close processes names specified. Custom description when adding "="
    echo          Before "=" : process name (Wildcard * compatible)
    echo          After  "=" : process Description (for description in popup)
    echo          Example: -Process "chrome=Google Chrome","acro*.exe=Adobe Acrobat"
    echo.
    echo       -ProcessPath (string list)
    echo          Close Exe files inside specified directory to terminate (Wildcard * compatible)
    echo          Example: -ProcessPath "C:\Program Files\Google\","C:\Program Files\Adobe*"
    echo.
    echo       -ProcessTitles (string list)
    echo          Close PID by window title. Can filter by process when adding "="
    echo          Before "=" : Window title (Wildcard * compatible)
    echo          After  "=" : Filter by process
    echo          Example: -ProcessTitles *paint,Message*=CSRSS.exe
    echo.
    echo       -ProcessDLL (string list)
    echo          Close processes that are using specified DLL (Wildcard * compatible)
    echo          Example: -ProcessDLL acroRd32.dll,"C:\Program Files\Adobe\*.dll"
    echo.
    echo       -PopupTitle (string)
    echo          NO POPUP IF MISSING. Display name of the product being installed.
    echo          Example: -PopupTitle "Adobe Acrobat"
    echo.
    echo       -Timer (int)
    echo          Countdown in seconds before forced termination.
    echo          Default: 600 (10 minutes)
    echo          Example: -Timer 300
    echo.
    echo       -Attempts (int)
    echo          Number of repeated termination attempts.
    echo          Default: 8
    echo          Example: -Attempts 5
    echo.
    echo       -Test (switch)
    echo          Runs in test mode: Show console + processes are not killed
    echo.
    echo       -Log (string)
    echo          Example: -Log "C:\Logs\CloseProcessPopup.log"
    echo.
    echo.
    echo    USAGE:
    echo       ------------
    echo.
    echo       ^> NORMAL
    echo       cmd /c ""C:\Path\CloseProcessPopup.bat" -PopupTitle "ADOBE" -Process "chrome.exe=Google Chrome","Acrord32=Acrobat Reader" -ProcessPath "C:\Program Files\Google","C:\Program Files\Adobe" -Log "C:\Logs""
    echo.
    echo       ^> SYSTEM 
    echo       schtasks /create /tn "SysPWSh" /tr "cmd /c \"\"C:\Path\backend.bat\" -Process \"chrome=chrome\" -PopupTitle \"ADOBE\" -test\"" /sc onstart /ru SYSTEM ^& schtasks /run /tn "SysPWSh" ^& schtasks /delete /tn "SysPWSh" /f
    echo.
    echo       ^> REMOTE 
    echo       powershell -Ex Bypass -Command "Invoke-Command -ComputerName ANY -Authentication Negotiate -Credential (New-Object System.Management.Automation.PSCredential('ANY\AdminName',(ConvertTo-SecureString 'AdminPassword' -AsPlainText -Force))) -ScriptBlock { param($batContent,$extraArgs) $Dest=\"$($env:SystemRoot)\Temp\CloseProcessPopup.bat\"; $utf8Bom = New-Object System.Text.UTF8Encoding $false; [System.IO.File]::WriteAllText($Dest,$batContent,$utf8Bom); ^& cmd.exe /c \"\"$Dest\" $extraArgs\"; $LASTEXITCODE } -ArgumentList (Get-Content -Path 'C:\SourcePath\CloseProcessPopup.bat' -Raw), '-Process \"Taskmgr.exe=Task Manager\" -Description \"Autodesk\" -test'"
    echo.    
    echo       ^> DOMAIN 
    echo       powershell -Ex Bypass -Command "Invoke-Command -ComputerName ANY -ScriptBlock { param($batContent,$extraArgs) $Dest=\"$($env:SystemRoot)\Temp\CloseProcessPopup.bat\"; $utf8Bom = New-Object System.Text.UTF8Encoding $false; [System.IO.File]::WriteAllText($Dest,$batContent,$utf8Bom); ^& cmd.exe /c \"\"$Dest\" $extraArgs\"; $LASTEXITCODE } -ArgumentList (Get-Content -Path 'C:\SourcePath\CloseProcessPopup.bat' -Raw), '-Process \"Taskmgr.exe=Task Manager\" -Description \"Autodesk\" -test'"
    echo.
    echo.
    echo.
    echo    EXIT CODES:
    echo       ------
    echo    0   = Success
    echo    1   = Unknown general launch/error
    echo    2   = No requested processes are currently running
    echo    21  = Failed to enumerate processes
    echo    22  = No interactive session open
    echo    3   = Timeout waiting Helper/Popup process
    echo    4   = Exception during Helper/Popup launch
    echo    5   = Failed to create pipe / write to STDIN
    echo    6   = WTSEnumerateSessions failed
    echo    7   = WTSQueryUserToken failed
    echo    8   = DuplicateTokenEx failed
    echo    9   = CreateProcessAsUser failed
    echo    10  = No Admin nor System privilege at launch
    echo    11  = Missing arguments
    echo    12  = Helper/Popup ExitCode unavailable
    echo    13  = Unsupported context
    echo    14  = Unknown context
    echo    15  = Some processes still running after taskkill
    echo.
    echo    =============================================================================
    echo.
    pause >nul & exit /b
#>

#requires -version 2.0
Param(
    [Parameter(Mandatory=$false)][Alias('ProductName','Product')]                     [string]$PopupTitle,     # -PopupTitle  "Adobe Acrobat" (NO POPUP IF MISSING)
    [Parameter(Mandatory=$false)][Alias('Processes','CloseProcess','CloseProcesses')] [string[]]$Process,      # -Process     "chrome=Google Chrome","acrobat.exe=Adobe Acrobat"
    [Parameter(Mandatory=$false)][Alias('Path','Paths')]                              [string[]]$ProcessPath,  # -ProcessPath "C:\Program Files\Google","C:\Program Files\Adobe"
    [Parameter(Mandatory=$false)][Alias('Title','Titles','ProcessTitles')]            [string[]]$ProcessTitle, # -ProcessDLL  acroRd32.dll,"C:\Program Files\Adobe\*.dll"
    [Parameter(Mandatory=$false)][Alias('DLL','DLLpattern','UnlockDLL')]              [string[]]$ProcessDLL,   # -ProcessDLL  acroRd32.dll,"C:\Program Files\Adobe\*.dll"
    [Parameter(Mandatory=$false)][Alias('CountDown')]                                 [int]$Timer=600,         # -Timer 600   (in seconds)
    [Parameter(Mandatory=$false)][Alias('Retry')]                                     [int]$Attempts=8,        # -Attempts 8  (kill process every second, 8 times)
    [Parameter(Mandatory=$false)][Alias('NoKill','ShowConsole')]                      [switch]$Test,           # -Test        (do not kill processes at end)
    [Parameter(Mandatory=$false)][Alias('LogFile','LogName','LogPath')]               [string]$Log             # -Log MyLog.log  OR  -Log C:\MyPath\MyLog.log
)
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Need Admin or System rights at launch"
    exit 10
}
if (-not ($process -or $ProcessPath -or $ProcessTitle)) {
    $warn = "ERROR: Incorrect arguments provided. Required arguments:`n" +
            "   -PopupTitle xxx  (if you want to show popup, otherwise no popup)`n" +
            "       AND`n" +
            "   -Process xxx   OR   -ProcessPath xxx   OR   -ProcessDLL xxx   OR   -ProcessTitle xxx`n"
    Write-Host $warn
    Write-Host "Arguments provided:`nPopupTitle= $PopupTitle`nProcess= $Process`nProcessPath= $ProcessPath`nLog= $Log"
    exit 11
}
$sys32    = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$sysNative= Join-Path $env:WINDIR "Sysnative\WindowsPowerShell\v1.0\powershell.exe"
$pwsh = if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and (Test-Path $sysNative)) { $sysNative } else { $sys32 }

# ------------------------- Native P/Invoke -------------------------
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;
public class StdStreamHolder {
    private System.IO.Stream _baseStream;
    public System.IO.Stream BaseStream { get { return _baseStream; } set { _baseStream = value; } }
}
public class StdStreamsProxy {
    private StdStreamHolder _stdout;
    private StdStreamHolder _stderr;
    public StdStreamHolder StandardOutput { get { return _stdout; } set { _stdout = value; } }
    public StdStreamHolder StandardError  { get { return _stderr; } set { _stderr = value; } }
}
public class AdvApi32 {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="CreateProcessAsUserW")] public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
}
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct STARTUPINFO { public int cb; public string lpReserved; public string lpDesktop; public string lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
[StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }
[StructLayout(LayoutKind.Sequential)] public struct LUID { public uint LowPart; public int HighPart; }
[StructLayout(LayoutKind.Sequential)] public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
[StructLayout(LayoutKind.Sequential)] public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }
public class WtsApi32 {
    [DllImport("wtsapi32.dll", SetLastError=true)] public static extern bool WTSQueryUserToken(int sessionId, out IntPtr Token);
    [DllImport("kernel32.dll")] public static extern int WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, out IntPtr ppSessionInfo, out int pCount);
    [DllImport("wtsapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, int wtsInfoClass, out IntPtr ppBuffer, out int pBytesReturned);
    [DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr pMemory);
}
[StructLayout(LayoutKind.Sequential)]
public struct WTS_SESSION_INFO { public int SessionId; public IntPtr pWinStationName; public int State; }
public class Win32Api {
    [Flags] public enum ProcessAccessFlags : uint { PROCESS_QUERY_INFORMATION=0x0400, PROCESS_VM_READ=0x0010 }
    [Flags] public enum ListModulesOptions : uint { LIST_MODULES_ALL=0x03 }
    public const int HANDLE_FLAG_INHERIT=0x1;
    [StructLayout(LayoutKind.Sequential)] public struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle; }
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetHandleInformation(IntPtr hObject, int dwMask, int dwFlags);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);
    [DllImport("psapi.dll", SetLastError = true)] public static extern bool EnumProcesses([MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] int[] processIds, int size, [MarshalAs(UnmanagedType.U4)] out int bytesReturned);
    [DllImport("psapi.dll", SetLastError = true)] public static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded);
    [DllImport("psapi.dll", CharSet = CharSet.Auto, SetLastError = true)]  public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, uint nSize);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)] public static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);
}
"@


# ==================================================================
#                            UTILITIES
# ==================================================================

function Stop-Script([int]$ExitCode) {
    try {Write-CustomLog "========================================="; Write-CustomLog "" -noprefix} catch {}
    exit $ExitCode
}

function Write-CustomLog { param([string]$Message, [switch]$NoPrefix)
    $ts = if (-not $NoPrefix.IsPresent) {Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"} else {$null}
    $line = "$(if(-not $NoPrefix.IsPresent){$ts+' - '})" + "$Message"
    try {
        $streamWriter = New-Object IO.StreamWriter($script:LogPath, $true, [Text.Encoding]::UTF8)
        $streamWriter.WriteLine($line)
    } catch {} finally { if ($streamWriter) { $streamWriter.Close() } }
    Write-Host $line
}

function Format-Name([string]$RawName) {
    # Normalizes PopupTitle name for filenames.
    $string = $RawName.Trim()
    $invalid = [IO.Path]::GetInvalidFileNameChars() + [IO.Path]::GetInvalidPathChars()
    foreach($ch in $invalid){ $string = $string -replace [Regex]::Escape([string]$ch), "_" }
    if ([string]::IsNullOrEmpty($string)) { $string = "Software" }
    elseif ($string.Length -gt 200) { $string = $string.Substring(0,200) }
    return $string
}

function Resolve-LogPath([string]$Title,[string]$CandidateLog) {
    # Define the log file path. Creates the folder if missing.
    $defaultName = "${Title}_CloseProcessPopup.log"
    if ([string]::IsNullOrEmpty($CandidateLog)) { $path = Join-Path "$env:SystemRoot\Temp" $defaultName }
    elseif ($CandidateLog -match '[\\/]' -and (Test-Path $CandidateLog -PathType Container)) { $path = Join-Path $CandidateLog $defaultName }
    else {
        $leaf = if ($CandidateLog -match '[\\/]') { [IO.Path]::GetFileName($CandidateLog) } else { $CandidateLog }
        if ($leaf -notmatch 'popup') { $leaf = [IO.Path]::GetFileNameWithoutExtension($leaf) + "_CloseProcessPopup" + [IO.Path]::GetExtension($leaf) }
        if ([string]::IsNullOrEmpty([IO.Path]::GetExtension($leaf))) { $leaf += ".log" }
        $dir = if ($CandidateLog -match '[\\/]') { Split-Path $CandidateLog -Parent } else { $null }
        if (-not $dir) { $dir = Join-Path $env:SystemRoot "Temp" }
        $path = Join-Path $dir $leaf
    }
    $parentDir = [IO.Path]::GetDirectoryName($path)
    if (-not (Test-Path -LiteralPath $parentDir -PathType Container)) { New-Item -Path $parentDir -Type Directory -Force | Out-Null  }
    return $path
}


# ==================================================================
#                              DISCOVERY
# ==================================================================

function Get-SessionContext {
    $currentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $sessionContext = @{
        Name                     = $currentIdentity.Name
        IsSystem                 = $currentIdentity.IsSystem
        IsAdmin                  = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        IsProcessInteractive     = [Environment]::UserInteractive
        SessionName              = $env:SESSIONNAME
        CurrentProcessSessionId  = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        HasActiveUserSession     = $false
        ActiveUserSessionId      = $null
        ActiveUserSessionStation = $null
        ActiveUserDomain         = $null
        ActiveUserName           = $null
        ActiveUserFullName       = $null
    }
    try {
        $sessionsPointer = [IntPtr]::Zero; $sessionCount = 0
        if ([WtsApi32]::WTSEnumerateSessions([IntPtr]::Zero,0,1,[ref]$sessionsPointer,[ref]$sessionCount)) {
            $structSize = [Runtime.InteropServices.Marshal]::SizeOf([type]([WTS_SESSION_INFO]))
            $cursorPtr  = $sessionsPointer
            for ($i=0; $i -lt $sessionCount; $i++) {
                $sessionInfo = [Runtime.InteropServices.Marshal]::PtrToStructure($cursorPtr,[type]([WTS_SESSION_INFO]))
                $stationName = [Runtime.InteropServices.Marshal]::PtrToStringUni($sessionInfo.pWinStationName)
                # Update SessionName if it matches the current process session
                if ($sessionInfo.SessionId -eq $sessionContext.CurrentProcessSessionId) {
                    $sessionContext.SessionName = $stationName
                }
                # Active session (state=0 = Active, exclude "Services")
                if (($sessionInfo.State -eq 0) -and $stationName -and ($stationName -ne 'Services')) {
                    $sessionContext.HasActiveUserSession     = $true
                    $sessionContext.ActiveUserSessionId      = $sessionInfo.SessionId
                    $sessionContext.ActiveUserSessionStation = $stationName
                    # Retrieve username via WTSQuerySessionInformation (WTSUserName=5)
                    $pUser = [IntPtr]::Zero; $bytes = 0
                    if ([WtsApi32]::WTSQuerySessionInformation([IntPtr]::Zero,$sessionInfo.SessionId,5,[ref]$pUser,[ref]$bytes)) {
                        $userName = [Runtime.InteropServices.Marshal]::PtrToStringUni($pUser)
                        [WtsApi32]::WTSFreeMemory($pUser)
                        if ($userName) { $sessionContext.ActiveUserName = $userName }
                    }
                    # Retrieve domain name (WTSDomainName=7)
                    if ([WtsApi32]::WTSQuerySessionInformation([IntPtr]::Zero,$sessionInfo.SessionId,7,[ref]$pUser,[ref]$bytes)) {
                        $domainName = [Runtime.InteropServices.Marshal]::PtrToStringUni($pUser)
                        [WtsApi32]::WTSFreeMemory($pUser)
                        if ($domainName) { $sessionContext.ActiveUserDomain = $domainName }
                    }
                    # Build DOMAIN\User string if possible
                    if ($sessionContext.ActiveUserDomain -and $sessionContext.ActiveUserName) {
                        $sessionContext.ActiveUserFullName = "$($sessionContext.ActiveUserDomain)\$($sessionContext.ActiveUserName)"
                    } elseif ($sessionContext.ActiveUserName) {
                        $sessionContext.ActiveUserFullName = $sessionContext.ActiveUserName
                    }
                    break
                }
                $cursorPtr = New-Object IntPtr ($cursorPtr.ToInt64() + $structSize)
            }
            [WtsApi32]::WTSFreeMemory($sessionsPointer)
        }
    } catch {
        Write-CustomLog ("WTSEnumerateSessions exception: " + $_.Exception.Message)
        Stop-Script 6
    }
    return $sessionContext
}

function Get-RunningProcesses {
    <#
    Purpose : Build the detectedProcesses list with a single EnumProcesses scan (+ one EnumWindows pass if -ProcessTitle is used):
    - -Processes supports "*" wildcards on executable names ("chrome*.exe", "win* = My caption").
    - -ProcessesPaths is treated as raw wildcard patterns (use "*" where needed). No more implicit prefix/exact.
    - -ProcessDLL keeps wildcard support like before.
    - -ProcessTitle accepts wildcards too; syntax optionally supports "TitlePattern=ProcessNamePattern" to pre-filter by process name.
    - Aggregate PIDs by executable name for non-title sources; exit 2 if nothing is running.

    Returns detectedProcesses (array of hashtables):
        @{ Name; ShortName; Description; ExePath; IconBase64; Process_Ids[]; [CloseByPid=$true when source=Title] }
    #>
    param([int32]$SessionId, [string]$pwsh, [string[]]$Processes, [string[]]$ProcessesPaths, [string[]]$ProcessTitles, [string[]]$ProcessDLL )

    function Save-IconToBase64Png([System.Drawing.Icon]$Icon) {
        if (-not $Icon) { return $null }
        $bmp = $Icon.ToBitmap()
        $ms  = New-Object IO.MemoryStream
        try {
            $bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png)
            [Convert]::ToBase64String($ms.ToArray())
        } catch { $null } finally { $ms.Dispose(); $bmp.Dispose() }
    }

    # 1) -------------- Normalize the -Process entries (now supports wildcards) --------------
    $requestedByLowerName=@{}   # key => meta (for logging/description/source)
    $explicitNamesLower=@{}     # exact names only (to report "not running")
    $explicitNamePatterns=@()   # wildcard name patterns: @{ PatternLower; Description }
    $parsedProcessArgs=$Processes
    foreach($rawArgument in $parsedProcessArgs){
        if([string]::IsNullOrEmpty($rawArgument)){continue}
        $executableNameRaw=$rawArgument; $descriptionText=""
        if($rawArgument -like "*=*"){ $kv=$rawArgument -split "=",2; $executableNameRaw=$kv[0]; $descriptionText=$kv[1] }
        $executableName=[IO.Path]::GetFileName($executableNameRaw.Trim('"',' ','\','/'))
        if($executableName -notmatch '\.exe$'){ $executableName+='.exe' }
        $descriptionText=$descriptionText.Trim()
        $lowerPattern=$executableName.ToLowerInvariant()
        if($lowerPattern -like '*[*]*' -or $lowerPattern -like '*?*'){
            $explicitNamePatterns+=,@{PatternLower=$lowerPattern;Description=$descriptionText}
        }else{
            if(-not $requestedByLowerName.ContainsKey($lowerPattern)){
                $requestedByLowerName[$lowerPattern]=@{Name=$executableName;ShortName=($executableName -replace '\.exe$','');Description=$descriptionText;Source='Explicit';SourceDetail=$null}
                $explicitNamesLower[$lowerPattern]=$true
            }
        }
    }

    # 2) -------------- Normalize the -ProcessPath entries as wildcard patterns --------------
    # Each pattern entry: @{ PatternLower; RawInput }
    $pathPatterns=@()
    $parsedPathArgs=$ProcessesPaths
    foreach($pathArgument in $parsedPathArgs){
        if([string]::IsNullOrEmpty($pathArgument)){continue}
        $rawTrimmed=$pathArgument.Trim()
        $full=$rawTrimmed.Trim('"')
        try{ $full=[IO.Path]::GetFullPath($full) }catch{}
        if([string]::IsNullOrEmpty($full)){continue}
        $norm=(($full -replace '/','\')).ToLowerInvariant()
        $pathPatterns+=,@{PatternLower=$norm;RawInput=$rawTrimmed.Trim('"')}
    }
    if($pathPatterns.Count -gt 0){
        $normForLog=@(); foreach($r in $pathPatterns){ $normForLog+=("PATH:"+$r.PatternLower) }
        Write-CustomLog ("ProcessPath patterns: " + ($normForLog -join "; "))
    }

    # 3) -------------- Prepare DLL pattern --------------
    $dllPatternInfos=@()
    if($ProcessDLL -and $ProcessDLL.Count -gt 0){
        foreach($pattern in $ProcessDLL){
            if($pattern){
                $trimmed=$pattern.Trim()
                if($trimmed){
                    $dllPatternInfos+=New-Object PSObject -Property @{ PatternLower=$trimmed.ToLowerInvariant(); UseFileNameOnly=(-not ($trimmed -match '[\\/]')) }
                }
            }
        }
        if($dllPatternInfos.Count -gt 0){
            $patternsForLog=($ProcessDLL | Where-Object { $_ } | ForEach-Object { $_.Trim() }) -join ", "
            Write-CustomLog ("DLL patterns: " + $patternsForLog)
        }
    }

    # 4) -------------- Prepare Title queries --------------
    # Each entry: @{ TitlePatternLower; ProcNamePatternLower (nullable) }
    $titleQueries=@()
    if($ProcessTitles -and $ProcessTitles.Count -gt 0){
        foreach($arg in $ProcessTitles){
            if([string]::IsNullOrEmpty($arg)){continue}
            if($arg -like "*=*"){
                $kv=$arg -split "=",2
                $tpat=$kv[0].Trim()
                $ppat=[IO.Path]::GetFileName($kv[1].Trim()) # accept raw or path; keep file name only
                if($ppat -and ($ppat -notmatch '\.exe$')){ $ppat+='.exe' }
                $titleQueries+=,@{TitlePatternLower=$tpat.ToLowerInvariant();ProcNamePatternLower=($ppat.ToLowerInvariant())}
            }else{
                $titleQueries+=,@{TitlePatternLower=$arg.Trim().ToLowerInvariant();ProcNamePatternLower=$null}
            }
        }
        Write-CustomLog ("Title patterns: " + (($titleQueries | ForEach-Object { $_.TitlePatternLower }) -join "; "))
    }

    # 5) -------------- Enumerate all processes ONCE --------------
    $modulePathSB=New-Object System.Text.StringBuilder 1024
    $procPathSB=New-Object System.Text.StringBuilder 1024
    $pointerSize=[IntPtr]::Size
    $moduleHandles=New-Object IntPtr[] 256
    $processIds=New-Object int[] 2048
    $bytesReturned=0
    $detectedByKey=@{}
    $pidToNameLower=@{}; $pidToNameProper=@{}; $pidToExePath=@{}
    if(-not [Win32Api]::EnumProcesses($processIds,$processIds.Length*4,[ref]$bytesReturned)){ Write-CustomLog "Failed to enumerate processes"; Stop-Script 2 }
    $processCount=[int]($bytesReturned/4)
    for($processIndex=0;$processIndex -lt $processCount;$processIndex++){
        $processId=$processIds[$processIndex]; if($processId -eq 0){continue}
        $processHandle=[IntPtr]::Zero
        try{
            $access=[Win32Api+ProcessAccessFlags]::PROCESS_QUERY_INFORMATION -bor [Win32Api+ProcessAccessFlags]::PROCESS_VM_READ
            $processHandle=[Win32Api]::OpenProcess($access,$false,$processId)
            if($processHandle -eq [IntPtr]::Zero){continue}
            [void]$procPathSB.Remove(0,$procPathSB.Length)
            $len=$procPathSB.Capacity; $processFullPath=$null
            if ([Environment]::OSVersion.Version.Major -ge 6 -and [Win32Api]::QueryFullProcessImageName($processHandle,0,$procPathSB,[ref]$len)) { $processFullPath=$procPathSB.ToString() }
            else{
                try{ $wmi=Get-WmiObject -Class Win32_Process -Filter "ProcessId=$processId" -ErrorAction Stop; $processFullPath=(if($wmi.ExecutablePath){$wmi.ExecutablePath}else{$wmi.Name}) }catch{}
            }
            if([string]::IsNullOrEmpty($processFullPath)){continue}
            $processName=[System.IO.Path]::GetFileName($processFullPath)
            $lowerName=$processName.ToLowerInvariant()
            $pidToNameLower[$processId]=$lowerName; $pidToNameProper[$processId]=$processName; $pidToExePath[$processId]=$processFullPath

            # Check Explicit exact names first
            $isRelevant=$false; $source='Explicit'; $sourceDet=$null
            if($requestedByLowerName.ContainsKey($lowerName)){
                $isRelevant=$true; $source='Explicit'
            }else{
                # Check wildcard -Processes patterns
                if($explicitNamePatterns.Count -gt 0){
                    foreach($pat in $explicitNamePatterns){
                        if($lowerName -like $pat.PatternLower){
                            if(-not $requestedByLowerName.ContainsKey($lowerName)){
                                $requestedByLowerName[$lowerName]=@{Name=$processName;ShortName=($processName -replace '\.exe$','');Description=$pat.Description;Source='Explicit';SourceDetail=$pat.PatternLower}
                            }
                            $isRelevant=$true; $source='Explicit'; $sourceDet=$pat.PatternLower; break
                        }
                    }
                }
                # Check ProcessPath wildcard patterns
                if(-not $isRelevant -and $pathPatterns.Count -gt 0){
                    $procPathLower=($processFullPath -replace '/','\').ToLowerInvariant()
                    foreach($r in $pathPatterns){
                        if($procPathLower -like $r.PatternLower){
                            if(-not $requestedByLowerName.ContainsKey($lowerName)){
                                $requestedByLowerName[$lowerName]=@{Name=$processName;ShortName=($processName -replace '\.exe$','');Description=($processName -replace '\.exe$','');Source='Path';SourceDetail=$r.RawInput}
                            }
                            $isRelevant=$true; $source='Path'; $sourceDet=$r.RawInput; break
                        }
                    }
                }
            }

            # DLL patterns
            $matchedDlls=@()
            if($dllPatternInfos.Count -gt 0){
                $requiredBytes=0
                $bufferBytes=$moduleHandles.Length*$pointerSize
                if([Win32Api]::EnumProcessModules($processHandle,$moduleHandles,$bufferBytes,[ref]$requiredBytes)){
                    if($requiredBytes -gt $bufferBytes){
                        $moduleHandles=New-Object IntPtr[] ([int][math]::Ceiling($requiredBytes/[double]$pointerSize))
                        $bufferBytes=$moduleHandles.Length*$pointerSize
                        if(-not [Win32Api]::EnumProcessModules($processHandle,$moduleHandles,$bufferBytes,[ref]$requiredBytes)){ $requiredBytes=0 }
                    }
                    if($requiredBytes -gt 0){
                        $moduleCount=[int]($requiredBytes/$pointerSize)
                        for($moduleIndex=0;$moduleIndex -lt $moduleCount;$moduleIndex++){
                            $moduleHandle=$moduleHandles[$moduleIndex]
                            [void]$modulePathSB.Remove(0,$modulePathSB.Length)
                            [void][Win32Api]::GetModuleFileNameEx($processHandle,$moduleHandle,$modulePathSB,[uint32]$modulePathSB.Capacity)
                            $modulePath=$modulePathSB.ToString()
                            if([string]::IsNullOrEmpty($modulePath)){continue}
                            $modulePathLower=$modulePath.ToLowerInvariant()
                            $moduleFileLower=[System.IO.Path]::GetFileName($modulePathLower)
                            foreach($info in $dllPatternInfos){
                                if($info.UseFileNameOnly){
                                    if($moduleFileLower -like $info.PatternLower){ $matchedDlls+=$moduleFileLower; break }
                                }else{
                                    if($modulePathLower -like $info.PatternLower){ $matchedDlls+=$modulePath; break }
                                }
                            }
                        }
                    }
                }
                if($matchedDlls.Count -gt 0 -and -not $isRelevant){
                    if(-not $requestedByLowerName.ContainsKey($lowerName)){
                        $requestedByLowerName[$lowerName]=@{Name=$processName;ShortName=($processName -replace '\.exe$','');Description=($processName -replace '\.exe$','');Source='DLL';SourceDetail=(($matchedDlls | Select-Object -First 3) -join ", ")}
                    }
                    $isRelevant=$true; $source='DLL'; $sourceDet=(($matchedDlls | Select-Object -First 3) -join ", ")
                }
            }

            # Aggregate detected processes (name-based entries)
            if($isRelevant){
                if(-not $detectedByKey.ContainsKey($lowerName)){
                    $meta=$requestedByLowerName[$lowerName]
                    if(-not $meta){ $meta=@{Name=$processName;ShortName=($processName -replace '\.exe$','');Description=$processName;Source=$source;SourceDetail=$sourceDet}; $requestedByLowerName[$lowerName]=$meta }
                    $detectedByKey[$lowerName]=@{Name=$meta.Name;ShortName=$meta.ShortName;Description=$meta.Description;ExePath=$processFullPath;IconBase64=$null;Process_Ids=@()}
                }
                $acc=$detectedByKey[$lowerName]
                $acc.Process_Ids+=,$processId
                if(-not $acc.ExePath){ $acc.ExePath=$processFullPath }
            }
        }finally{ if($processHandle -ne [IntPtr]::Zero){[void][Win32Api]::CloseHandle($processHandle)} }
    }

    # 6) -------------- Title-based enumeration --------------
    if($titleQueries.Count -gt 0){
        Write-CustomLog "Enumerating windows from user session..."
        try { $windowEntries = Get-UserSessionWindows -SessionId $targetSessionId -Pwsh $pwsh } 
        catch {
            Write-CustomLog ("Get-UserSessionWindows threw: " + $_.Exception.Message)
            $windowEntries = @()
        }
        if(-not $windowEntries){ Write-CustomLog "  Window enumeration returned 0 items." }
        $windowEntries = @($windowEntries)
        foreach($window in $windowEntries){
            $windowTitle = $window.Title
            $windowTitleLower = ""
            if($windowTitle){ $windowTitleLower = $windowTitle.ToLowerInvariant() }
            $process_Id = [int]$window.PID
            $processExeNameInput = $window.Name
            if(-not $processExeNameInput){ $processExeNameInput = "unknown.exe" }
            $processExeName = [IO.Path]::GetFileName($processExeNameInput)
            $processExeLower = $processExeName.ToLowerInvariant()
            $processPath = $window.ExePath
            $iconBase64 = $window.IconBase64
            if(-not $pidToNameLower.ContainsKey($process_Id)){
                $pidToNameLower[$process_Id]=$processExeLower
                $pidToNameProper[$process_Id]=$processExeName
                $pidToExePath[$process_Id]=$processPath
            }
            $i = 0
            while($i -lt $titleQueries.Count){
                $query = $titleQueries[$i]
                $i = $i + 1
                if((-not $windowTitleLower) -or (-not ($windowTitleLower -like $query.TitlePatternLower))){
                    continue
                }
                if($query.ProcNamePatternLower -and (-not ($processExeLower -like $query.ProcNamePatternLower))){
                    continue
                }
                $key = ($processExeLower + '|' + $windowTitleLower)
                if(-not $detectedByKey.ContainsKey($key)){
                    $shortNameVal = ($processExeName -replace '\.exe$','')
                    $detectedByKey[$key] = @{
                        Name        = $processExeName
                        ShortName   = $shortNameVal
                        Description = $windowTitle
                        ExePath     = $processPath
                        IconBase64  = $iconBase64
                        Process_Ids = @()
                        CloseByPid  = $true
                    }
                    $requestedByLowerName[$key] = @{
                        Name        = $processExeName
                        ShortName   = $shortNameVal
                        Description = $windowTitle
                        Source      = 'Title'
                        SourceDetail= $windowTitle
                    }
                }
                ($detectedByKey[$key].Process_Ids) += ,$process_Id
            }
        }
    }

    # 7) -------------- Attach icons for entries still missing them (name/path/dll) --------------
    if($detectedByKey.Count -ge 1){
        Add-Type -AssemblyName System.Drawing
        $iconCacheByExePathLower=@{}
        foreach($key in $detectedByKey.Keys){
            $acc=$detectedByKey[$key]
            if($acc.IconBase64){ continue }
            $iconBase64=$null; $firstPath=$acc.ExePath
            if($firstPath -and (Test-Path -LiteralPath $firstPath)){
                $exePathLower=$firstPath.ToLowerInvariant()
                if($iconCacheByExePathLower.ContainsKey($exePathLower)){ $iconBase64=$iconCacheByExePathLower[$exePathLower] }
                else{
                    try{
                        $iconObject=[System.Drawing.Icon]::ExtractAssociatedIcon($firstPath)
                        if($iconObject){ $iconBase64=Save-IconToBase64Png $iconObject }
                    }catch{}
                    if(-not $iconBase64){ $iconBase64=Save-IconToBase64Png ([System.Drawing.SystemIcons]::Application) }
                    $iconCacheByExePathLower[$exePathLower]=$iconBase64
                }
            }else{
                $iconBase64=Save-IconToBase64Png ([System.Drawing.SystemIcons]::Application)
            }
            $acc.IconBase64=$iconBase64
        }
    }

    # 8) -------------- Logging & return --------------
    $detectedProcesses=@(); foreach($k in $detectedByKey.Keys){ $detectedProcesses+=,$detectedByKey[$k] }
    $runningForLog=@()
    foreach($k in $detectedByKey.Keys){
        $entry=$detectedByKey[$k]; $meta=$requestedByLowerName[$k]
        $src=if($meta -and $meta.Source){ $meta.Source.ToUpper() }else{ 'EXPLICIT' }
        $pidsDisplay=($entry.Process_Ids) -join ","
        if($meta -and $meta.Source -eq 'Path'){
            $runningForLog+=(" -> [{0}] {1}`n     Match: {2}`n     PIDs: {3}" -f $src,$entry.Name,$entry.ExePath,$pidsDisplay)
        }elseif($meta -and $meta.Source -eq 'DLL'){
            $runningForLog+=(" -> [{0}] {1}`n     DLL: {2}`n     Process: {3}`n     PIDs: {4}" -f $src,$entry.Name,$meta.SourceDetail,$entry.ExePath,$pidsDisplay)
        }elseif($meta -and $meta.Source -eq 'Title'){
            $runningForLog+=(" -> [{0}] {1}`n     Title: {2}`n     Process: {3}`n     PIDs: {4}" -f $src,$entry.Name,$entry.Description,$entry.ExePath,$pidsDisplay)
        }else{
            $runningForLog+=(" -> [{0}] {1}`n     Source: {2}`n     PIDs: {3}" -f $src,$entry.Name,$entry.ExePath,$pidsDisplay)
        }
    }
    $missingExplicitNames=@()
    foreach($lowerKey in $requestedByLowerName.Keys){
        if($explicitNamesLower.ContainsKey($lowerKey) -and (-not $detectedByKey.ContainsKey($lowerKey))){
            $missingExplicitNames+=$requestedByLowerName[$lowerKey].Name
        }
    }
    Write-CustomLog ("Items built: count=" + $detectedProcesses.Count)
    if($runningForLog.Count -gt 0){
        Write-CustomLog (" Running found:") -NoPrefix
        foreach($line in $runningForLog){ Write-CustomLog "$line`n------" -NoPrefix }
    }
    if($missingExplicitNames.Count -gt 0){
        $missingDisplay=($missingExplicitNames | Sort-Object -Unique) -join ", "
        Write-CustomLog (" Not running: " + $missingDisplay) -NoPrefix
    }
    if($detectedProcesses.Count -eq 0){ Write-CustomLog "No requested processes are currently running. Exiting with code 2."; Stop-Script 2 }
    return ,$detectedProcesses
}

function Get-UserSessionWindows {
    param(
        [Parameter(Mandatory=$true)][int]$SessionId,
        [Parameter(Mandatory=$true)][string]$Pwsh
    )
    # spawn a helper in the user session; prints TSV: PID<TAB>Title<TAB>ExePath<TAB>Name<TAB>IconBase64
$helper_UserSessionWindows = @"
Add-Type -AssemblyName System.Drawing
function Write-HelperLog([string]`$msg){
    if (`$$($Test.IsPresent)) {
        try{
            `$ts=(Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff")
            Add-Content -LiteralPath "C:\Windows\temp\helper_UserSessionWindows.log" -Value "`$ts `$msg" -Encoding UTF8
        }catch{}
    }
}
Write-HelperLog "=== Helper started ==="
Write-HelperLog ("LanguageMode=" + `$ExecutionContext.SessionState.LanguageMode)
Write-HelperLog ("CLR=" + [System.Environment]::Version + "  PS=" + `$PSVersionTable.PSVersion)
Write-HelperLog ("ApartmentState=" + [Threading.Thread]::CurrentThread.ApartmentState)
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    try {
        [Threading.Thread]::CurrentThread.TrySetApartmentState([Threading.ApartmentState]::STA) | Out-Null
        Write-HelperLog "Forced ApartmentState=STA"
    } catch {
        Write-HelperLog ("Failed to set STA: " + `$_.Exception.Message)
    }
}

# --- Win32 interop (only what we need for window enumeration) ---
Add-Type @'
using System;using System.Text;using System.Runtime.InteropServices;
public class Win32Api2{public delegate bool EnumWindowsProc(IntPtr hWnd,IntPtr lParam);
[DllImport("user32.dll")]public static extern bool EnumWindows(EnumWindowsProc cb,IntPtr lParam);
[DllImport("user32.dll")]public static extern bool IsWindowVisible(IntPtr hWnd);
[DllImport("user32.dll",CharSet=CharSet.Unicode)]public static extern int GetWindowTextLength(IntPtr hWnd);
[DllImport("user32.dll",CharSet=CharSet.Unicode)]public static extern int GetWindowText(IntPtr hWnd,StringBuilder s,int n);
[DllImport("user32.dll")]public static extern int GetWindowThreadProcessId(IntPtr hWnd,out int pid);}
public class K32{[Flags]public enum Access:uint{QI=0x0400,VMREAD=0x0010}
[DllImport("kernel32.dll",SetLastError=true)]public static extern IntPtr OpenProcess(Access a,bool ih,int pid);
[DllImport("kernel32.dll",CharSet=CharSet.Auto,SetLastError=true)]public static extern bool QueryFullProcessImageName(IntPtr h,int flags,StringBuilder sb,ref int size);
[DllImport("kernel32.dll",SetLastError=true)]public static extern bool CloseHandle(IntPtr h);}
'@ -ErrorAction Stop

# --- Shell COM interop (minimal for AUMID(Path) → icon) ---
`$script:ShellInteropReady = `$false
try{
    Add-Type -ReferencedAssemblies 'System.Drawing' @'
using System;using System.Runtime.InteropServices;using System.Text;
[StructLayout(LayoutKind.Sequential)]public struct SIZE{public int cx;public int cy;}
[Flags]public enum SIIGBF:int{RESIZETOFIT=0x00,BIGGERSIZEOK=0x01,MEMORYONLY=0x02,ICONONLY=0x04,THUMBNAILONLY=0x08,INCACHEONLY=0x10,SCALEUP=0x200}
[ComImport,Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]public interface IShellItem{}
[ComImport,Guid("bcc18b79-ba16-442f-80c4-8a59c30c463b"),InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]public interface IShellItemImageFactory{int GetImage(SIZE size,SIIGBF flags,out IntPtr phbm);}
internal static class Gdi{public const int BI_RGB=0;
[StructLayout(LayoutKind.Sequential)]public struct BITMAP{public int bmType,bmWidth,bmHeight,bmWidthBytes;public ushort bmPlanes,bmBitsPixel;public IntPtr bmBits;}
[StructLayout(LayoutKind.Sequential)]public struct BITMAPINFOHEADER{public int biSize,biWidth,biHeight;public short biPlanes,biBitCount;public int biCompression,biSizeImage,biXPelsPerMeter,biYPelsPerMeter,biClrUsed,biClrImportant;}
[StructLayout(LayoutKind.Sequential)]public struct BITMAPINFO{public BITMAPINFOHEADER bmiHeader;public int bmiColors;}
[DllImport("gdi32.dll")]public static extern int GetObject(IntPtr hgdiobj,int cbBuffer,out BITMAP lpvObject);
[DllImport("gdi32.dll")]public static extern int GetDIBits(IntPtr hdc,IntPtr hbmp,int uStartScan,int cScanLines,IntPtr lpvBits,ref BITMAPINFO lpbi,int uUsage);
[DllImport("gdi32.dll")]public static extern bool DeleteObject(IntPtr hObject);
[DllImport("user32.dll")]public static extern IntPtr GetDC(IntPtr hWnd);
[DllImport("user32.dll")]public static extern int ReleaseDC(IntPtr hWnd,IntPtr hDC);}
public static class ShellInterop{
[DllImport("shell32.dll",CharSet=CharSet.Unicode)]public static extern int SHParseDisplayName(string name,IntPtr pbc,out IntPtr ppidl,uint sfgaoIn,out uint psfgaoOut);
[DllImport("shell32.dll")]public static extern int SHCreateItemFromIDList(IntPtr pidl,ref Guid riid,[MarshalAs(UnmanagedType.Interface)]out IShellItem ppv);
[DllImport("ole32.dll")]public static extern void CoTaskMemFree(IntPtr pv);
private static System.Drawing.Bitmap HBitmapToBitmapWithAlpha(IntPtr hbm){
    if(hbm==IntPtr.Zero)return null;Gdi.BITMAP bm;
    if(Gdi.GetObject(hbm,Marshal.SizeOf(typeof(Gdi.BITMAP)),out bm)==0)return null;
    Gdi.BITMAPINFO bi=new Gdi.BITMAPINFO();
    bi.bmiHeader.biSize=Marshal.SizeOf(typeof(Gdi.BITMAPINFOHEADER));
    bi.bmiHeader.biWidth=bm.bmWidth;bi.bmiHeader.biHeight=-Math.Abs(bm.bmHeight);
    bi.bmiHeader.biPlanes=1;bi.bmiHeader.biBitCount=32;bi.bmiHeader.biCompression=Gdi.BI_RGB;
    int srcStride=bm.bmWidth*4;int rows=Math.Abs(bm.bmHeight);int bytes=srcStride*rows;
    IntPtr hdc=Gdi.GetDC(IntPtr.Zero);IntPtr buf=Marshal.AllocHGlobal(bytes);
    try{
        int got=Gdi.GetDIBits(hdc,hbm,0,rows,buf,ref bi,0);if(got==0)return null;
        System.Drawing.Bitmap bmp=new System.Drawing.Bitmap(bm.bmWidth,rows,System.Drawing.Imaging.PixelFormat.Format32bppPArgb);
        System.Drawing.Rectangle rect=new System.Drawing.Rectangle(0,0,bm.bmWidth,rows);
        System.Drawing.Imaging.BitmapData data=bmp.LockBits(rect,System.Drawing.Imaging.ImageLockMode.WriteOnly,bmp.PixelFormat);
        try{
            int dstStride=Math.Abs(data.Stride);
            if(dstStride==srcStride){byte[] tmp=new byte[bytes];Marshal.Copy(buf,tmp,0,bytes);Marshal.Copy(tmp,0,data.Scan0,bytes);}
            else{byte[] line=new byte[srcStride];for(int y=0;y<rows;y++){IntPtr srcLine=new IntPtr(buf.ToInt64()+y*srcStride);Marshal.Copy(srcLine,line,0,srcStride);IntPtr dstLine=new IntPtr(data.Scan0.ToInt64()+y*dstStride);Marshal.Copy(line,0,dstLine,srcStride);}}
        }finally{bmp.UnlockBits(data);}
        return bmp;
    }finally{if(hdc!=IntPtr.Zero)Gdi.ReleaseDC(IntPtr.Zero,hdc);Marshal.FreeHGlobal(buf);Gdi.DeleteObject(hbm);}
}
private static System.Drawing.Bitmap GetIconFromIShellItem(IShellItem shellItem,int size){
    if(shellItem==null)return null;Guid iidFactory=typeof(IShellItemImageFactory).GUID;
    IntPtr unk=Marshal.GetIUnknownForObject(shellItem);
    try{
        IntPtr ppv;Guid riid=iidFactory;int hrQI=Marshal.QueryInterface(unk,ref riid,out ppv);
        if(hrQI!=0||ppv==IntPtr.Zero)return null;
        try{
            IShellItemImageFactory factory=(IShellItemImageFactory)Marshal.GetObjectForIUnknown(ppv);
            SIZE s; s.cx=size; s.cy=size; IntPtr hbm;
            int hrImg=factory.GetImage(s,SIIGBF.ICONONLY|SIIGBF.RESIZETOFIT|SIIGBF.BIGGERSIZEOK|SIIGBF.SCALEUP,out hbm);
            if(hrImg!=0||hbm==IntPtr.Zero)return null;
            return HBitmapToBitmapWithAlpha(hbm);
        }finally{Marshal.Release(ppv);}
    }finally{Marshal.Release(unk);}
}
public static System.Drawing.Bitmap GetIconFromAumid(string aumid,int size){
    if(string.IsNullOrEmpty(aumid))return null;uint dummy;IntPtr pidl;
    int hr=SHParseDisplayName("shell:AppsFolder\\"+aumid,IntPtr.Zero,out pidl,0,out dummy);
    if(hr!=0||pidl==IntPtr.Zero)return null;
    try{
        Guid iidShellItem=new Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE");IShellItem item;
        hr=SHCreateItemFromIDList(pidl,ref iidShellItem,out item);
        if(hr!=0||item==null)return null;return GetIconFromIShellItem(item,size);
    }finally{CoTaskMemFree(pidl);}
}
}
'@ -ErrorAction Stop

    `$null = [ShellInterop]
    `$script:ShellInteropReady = `$true
    Write-HelperLog "ShellInterop loaded OK."
}
catch{
    `$script:ShellInteropReady = `$false
    Write-HelperLog ("Add-Type(ShellInterop) FAILED: " + `$_.Exception.ToString())
}

function Sanitize([string]`$text){ if(-not `$text){return ""}; (`$text -replace "[`t`r`n]"," ") }

function Get-ExePath([int]`$processId){
    try{
        `$proc = Get-Process -Id `$processId -ErrorAction Stop
        if(`$proc -and `$proc.Path){ return `$proc.Path }
    }catch{}
    `$processHandle=[IntPtr]::Zero
    try{
        `$access = [enum]::ToObject([K32+Access],0x1000) # PROCESS_QUERY_LIMITED_INFORMATION
        `$processHandle=[K32]::OpenProcess(`$access,`$false,`$processId)
        if(`$processHandle -ne [IntPtr]::Zero){
            `$pathBuilder=New-Object System.Text.StringBuilder 1024; `$lenRef=`$pathBuilder.Capacity
            if([K32]::QueryFullProcessImageName(`$processHandle,0,`$pathBuilder,[ref]`$lenRef)){ return `$pathBuilder.ToString() }
        }
    }catch{} finally{ if(`$processHandle -ne [IntPtr]::Zero){ [K32]::CloseHandle(`$processHandle) | Out-Null } }
    `$processHandle=[IntPtr]::Zero
    try{
        `$processHandle=[K32]::OpenProcess([K32+Access]::QI -bor [K32+Access]::VMREAD,`$false,`$processId)
        if(`$processHandle -ne [IntPtr]::Zero){
            `$pathBuilder=New-Object System.Text.StringBuilder 1024; `$lenRef=`$pathBuilder.Capacity
            if([K32]::QueryFullProcessImageName(`$processHandle,0,`$pathBuilder,[ref]`$lenRef)){ return `$pathBuilder.ToString() }
        }
    }catch{} finally{ if(`$processHandle -ne [IntPtr]::Zero){ [K32]::CloseHandle(`$processHandle) | Out-Null } }
    try{
        `$cimProc = Get-CimInstance Win32_Process -Filter "ProcessId=`$processId" -ErrorAction SilentlyContinue
        if(`$cimProc -and `$cimProc.ExecutablePath){ return `$cimProc.ExecutablePath }
    }catch{}
    return `$null
}

# Derive AUMID from a WindowsApps path by reading AppxManifest.xml
function Get-AumidFromWindowsAppsPath([string]`$exePath){
    try{
        if(-not `$exePath -or (`$exePath -notlike "*\WindowsApps\*")){ return `$null }
        `$packageRoot = Split-Path -Parent `$exePath
        for(`$i=0; `$i -lt 4 -and -not (Test-Path (Join-Path `$packageRoot "AppxManifest.xml")); `$i++){
            `$packageRoot = Split-Path -Parent `$packageRoot
        }
        `$manifestPath = Join-Path `$packageRoot "AppxManifest.xml"
        if(-not (Test-Path `$manifestPath)){ Write-HelperLog "Get-Aumid: no manifest"; return `$null }
        `$leafFolder = Split-Path -Leaf `$packageRoot
        `$regexMatch = [regex]::Match(`$leafFolder,'^(?<name>[^_]+)_[^_]+_[^_]+__?(?<pubid>[^\\]+)`$')
        if(-not `$regexMatch.Success){ Write-HelperLog ("Get-Aumid: regex miss on '{0}'" -f `$leafFolder); return `$null }
        `$packageFamily = `$regexMatch.Groups['name'].Value + "_" + `$regexMatch.Groups['pubid'].Value
        [xml]`$manifestXml = Get-Content -LiteralPath `$manifestPath -Encoding UTF8
        `$applicationNode = `$manifestXml.Package.Applications.Application
        if(-not `$applicationNode){ Write-HelperLog "Get-Aumid: no <Application>"; return `$null }
        `$appId = [string]`$applicationNode.Id
        if(-not `$appId){ Write-HelperLog "Get-Aumid: empty AppId"; return `$null }
        `$packageFamily + "!" + `$appId
    }catch{
        Write-HelperLog ("Get-Aumid EX: " + `$_.Exception.Message)
        `$null
    }
}

function Bitmap-ToBase64Png([System.Drawing.Bitmap]`$bitmap){
    if(-not `$bitmap){ return "" }
    `$memStream = New-Object System.IO.MemoryStream
    try{
        `$bitmap.Save(`$memStream,[System.Drawing.Imaging.ImageFormat]::Png)
        [Convert]::ToBase64String(`$memStream.ToArray())
    }catch{ "" }finally{
        try{`$memStream.Dispose()}catch{}
        try{`$bitmap.Dispose()}catch{}
    }
}

function Get-IconBitmap-FromHwnd([IntPtr]`$hWnd,[string]`$exePath,[int]`$reqSize=96){
<#
Priority:
  1) AUMID from WindowsApps path → ShellInterop.GetIconFromAumid
  2) ExtractAssociatedIcon(exePath)
Fallback: SystemIcons.Application.
#>
    function _Try([scriptblock]`$sb,[string]`$tag){
        try{& `$sb}catch{Write-HelperLog "[`$tag] EX: `$(`$_.Exception.Message)";`$null}
    }
    if(`$script:ShellInteropReady){
        if(`$exePath -and `$exePath -like "*\WindowsApps\*"){
            `$aumidFromPath=_Try { Get-AumidFromWindowsAppsPath `$exePath } 'AUMID.FromPath'
            if(`$aumidFromPath){
                `$iconBitmap=_Try { [ShellInterop]::GetIconFromAumid(`$aumidFromPath,`$reqSize) } 'ShellInterop.GetIconFromAumid(Path)'
                if(`$iconBitmap){ Write-HelperLog "[AUMID(Path)] OK"; return `$iconBitmap } else { Write-HelperLog "[AUMID(Path)] NULL" }
            } else { Write-HelperLog "[AUMID(Path)] NotFound" }
        }
    } else { Write-HelperLog "[ShellInterop] NotAvailable" }

    if(`$exePath){
        `$iconObj=_Try { [System.Drawing.Icon]::ExtractAssociatedIcon(`$exePath) } 'ExtractAssociatedIcon'
        if(`$iconObj){
            `$bitmap=_Try { `$iconObj.ToBitmap() } 'Icon.ToBitmap'
            if(`$bitmap){ Write-HelperLog "[ExtractAssociatedIcon] OK"; return `$bitmap } else { Write-HelperLog "[ExtractAssociatedIcon] NULL.Bmp" }
        } else { Write-HelperLog "[ExtractAssociatedIcon] NULL.Icon" }
    } else { Write-HelperLog "[ExtractAssociatedIcon] No exePath" }

    Write-HelperLog "[Fallback] SystemIcons.Application"
    [System.Drawing.SystemIcons]::Application.ToBitmap()
}

# Enumerate windows
`$windowList = New-Object System.Collections.ArrayList
[Win32Api2]::EnumWindows({ param(`$windowHandle,`$unused)
    if(-not [Win32Api2]::IsWindowVisible(`$windowHandle)){ return `$true }
    `$titleLength=[Win32Api2]::GetWindowTextLength(`$windowHandle)
    if(`$titleLength -le 0){ return `$true }
    `$titleBuilder=New-Object System.Text.StringBuilder (`$titleLength+1)
    if([Win32Api2]::GetWindowText(`$windowHandle,`$titleBuilder,`$titleBuilder.Capacity) -eq 0){ return `$true }
    `$title=`$titleBuilder.ToString()
    if(-not `$title -or `$title -match '^\s*`$'){ return `$true }   # remplace IsNullOrWhiteSpace
    `$null = `$windowList.Add(@{ H=`$windowHandle; Title=`$title })
    return `$true
}, [IntPtr]::Zero) | Out-Null
Write-HelperLog ("Enumerated " + `$windowList.Count + " windows")

# Emit TSV
foreach(`$win in `$windowList){
    `$processId = 0; [void][Win32Api2]::GetWindowThreadProcessId(`$win.H,[ref]`$processId)
    `$exePath = Get-ExePath `$processId
    Write-HelperLog ("Window '{0}' PID={1} Path={2}" -f `$win.Title, `$processId, (`$(if (`$exePath) { `$exePath } else { "<null>" })))

    `$iconBitmap = Get-IconBitmap-FromHwnd `$win.H `$exePath 32
    `$iconBase64 = Bitmap-ToBase64Png `$iconBitmap
    if(`$iconBase64.Length -gt 0){ Write-HelperLog (" -> Icon Base64 length=" + `$iconBase64.Length) } else { Write-HelperLog " -> Icon Base64 EMPTY" }

    `$processNameOut=""
    try{
        if(`$processId -gt 0){
            `$proc=Get-Process -Id `$processId -ErrorAction SilentlyContinue
            if(`$proc){ `$processNameOut = (`$proc.ProcessName + ".exe") }
        }
    }catch{}

    `$pidOut   = [string]`$processId
    `$titleOut = (Sanitize `$win.Title)
    `$pathOut  = (Sanitize `$exePath)
    `$nameOut  = (Sanitize `$processNameOut)
    `$iconOut  = if(`$iconBase64){ (`$iconBase64 -replace "`r|`n","") } else { "" }

    [Console]::Out.WriteLine(`$pidOut + "`t" + `$titleOut + "`t" + `$pathOut + "`t" + `$nameOut + "`t" + `$iconOut)
}

Write-HelperLog "=== Helper end ==="
"@

    $isSystemAccount = ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem)
    $spawnResult = $null
    try {
        if ($isSystemAccount) { $spawnResult = Start-FromSystemAsCurrentUser -SessionId $SessionId -Pwsh $Pwsh -Script $helper_UserSessionWindows -ShowWindow:$Test.IsPresent -TimeoutSeconds 60} 
        else                  { $spawnResult = Start-FromCurrentUserStdin -Script $helper_UserSessionWindows}
    } catch { Write-CustomLog (($(if($isSystemAccount){"Start-FromSystemAsCurrentUser"}else{"Start-FromCurrentUserStdin"})) + " threw: " + $_.Exception.Message) }
    if(-not $spawnResult){
        Write-CustomLog "No Window-Title result from helper."
        return @()
    }
    $succVal = $spawnResult.Success
    $exitVal = $spawnResult.ExitCode
    $pidVal  = $spawnResult.Process_Id
    Write-CustomLog ("Helper exited. Success=" + $succVal + " ExitCode=" + $exitVal + " PID=" + $pidVal)
    # Get STDOUT
    $stdoutRaw = $spawnResult.Stdout
    if (-not $stdoutRaw -and $spawnResult.Output) { $stdoutRaw = $spawnResult.Output }  # compat éventuelle
    if ($stdoutRaw -is [string]) { $stdoutRaw = @($stdoutRaw -split "`r?`n") }
    $lineCount = 0
    if($stdoutRaw){ $lineCount = $stdoutRaw.Count }
    Write-CustomLog ("STDOUT lines: " + $lineCount)
    if(-not $stdoutRaw -and -not $isSystemAccount){
        Write-CustomLog "[WARN] No stdout captured from Start-FromCurrentUserStdin. Ensure it redirects and returns Stdout."
    }
    $nonTsv = 0
    $stdoutLines = @()
    if($stdoutRaw){
        foreach($l in $stdoutRaw){
            if($l -and ($l -match "`t")){ $stdoutLines+=,$l } else { $nonTsv = $nonTsv + 1 }
        }
    }
    if($nonTsv -gt 0){ Write-CustomLog ("Non-TSV lines ignored: " + $nonTsv) }
    # --- Title normalization (outside helper) ---
    function Convert-FuzzyTitle {
        param(
            [string]$s,
            [switch]$PreserveSpaces
        )
        if(-not $s){ return "" }
        # Replace a wide range of unicode spaces with ASCII space
        $spaces = @(0x00A0,0x1680,0x2000,0x2001,0x2002,0x2003,0x2004,0x2005,0x2006,0x2007,0x2008,0x2009,0x200A,0x202F,0x205F,0x3000)
        foreach($cp in $spaces){ $s = $s -replace ([string][char]$cp), ' ' }
        # Remove zero-width stuff
        $s = $s -replace ([string][char]0x200B),'' -replace ([string][char]0x200C),'' -replace ([string][char]0x200D),'' -replace ([string][char]0xFEFF),''
        # Normalize fancy dashes to '-'
        $dashes = @(0x2010,0x2011,0x2012,0x2013,0x2014,0x2015,0x2212)
        foreach($cp in $dashes){ $s = $s -replace ([string][char]$cp), '-' }
        # Unify controls to ASCII space
        $s = $s -replace "[`\t`r`n]+", " "
        if(-not $PreserveSpaces){ $s = $s -replace " {2,}", " " }
        $s = $s.Trim()
        return $s
    }
    $parsedList = @()
    foreach($stdoutLine in $stdoutLines){
        $parts = $stdoutLine -split "`t",5
        if($parts.Length -ge 5){
            $process_Id=[int]$parts[0]
            $windowTitle=$parts[1]
            $exePath=$parts[2]
            $procName=$parts[3]
            $iconBase64=$parts[4]
            # Build both normalized variants
            $altColl = Convert-FuzzyTitle -s $windowTitle
            $altKeep = Convert-FuzzyTitle -s $windowTitle -PreserveSpaces
            # Choose the returned title (prefers collapsed, then preserved, then original)
            $titleChosen = if([string]::IsNullOrEmpty($altColl)) {
                if([string]::IsNullOrEmpty($altKeep)) { $windowTitle } else { $altKeep }
            } else { $altColl }

            if($titleChosen -ne $windowTitle){
                Write-CustomLog ("Title chosen (normalized) : '{0}' => '{1}'" -f $windowTitle,$titleChosen)
            }
            $parsedList+=,[pscustomobject]@{
                PID       = $process_Id
                Title     = $titleChosen
                ExePath   = $exePath
                Name      = $procName
                IconBase64= $iconBase64
            }
        } else {
            Write-CustomLog ("TSV parse failed for line: " + $stdoutLine)
        }
    }
    $parsedCount = 0
    if($parsedList){ $parsedCount = $parsedList.Count }
    Write-CustomLog ("Parsed windows: " + $parsedCount)
    return ,$parsedList
}


# ==================================================================
#                           Scripts STARTERS
# ==================================================================

function Start-FromCurrentUserStdin {
    <#
    Purpose: Run the provided script text in-process (same PowerShell).
    Args are passed positionally to the scriptblock.
    Returns:
      @{ Success=[bool]; ExitCode=[int]; Process_Id=[int]; Error=[string|null]; Stdout=[string[]]; Stderr=[string[]] }
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Script,
        [Parameter(Mandatory=$false)][object[]]$Arguments=@()
    )
    Write-CustomLog ("Start-FromCurrentUserStdin(in-proc): compiling script; args count={0}" -f $Arguments.Count)
    $sb=$null
    try   { $sb=[ScriptBlock]::Create($Script) }
    catch {
        Write-CustomLog ("Start-FromCurrentUserStdin: compile error: " + $_.Exception.Message)
        return @{ Success=$false; ExitCode=2; Process_Id=$PID; Error=("Script compile error: " + $_.Exception.Message); Stdout=@(); Stderr=@() }
    }
    # Capture Console.Out during execution (helper writes TSV via [Console]::Out)
    $oldOut=[Console]::Out
    $sw=New-Object IO.StringWriter
    [Console]::SetOut($sw)
    $oldEAP=$ErrorActionPreference
    $stderrBuf=New-Object System.Collections.Generic.List[string]
    try{
        $ErrorActionPreference='Stop'
        # Execute with arguments passed positionally
        & $sb @Arguments | Out-Null
        $stdoutText=$sw.ToString()
        $stdoutLines=@(); if($stdoutText){ $stdoutLines=@($stdoutText -split "`r?`n") }
        Write-CustomLog ("Start-FromCurrentUserStdin: success, stdout lines=" + $stdoutLines.Count)
        return @{ Success=$true; ExitCode=0; Process_Id=$PID; Error=$null; Stdout=$stdoutLines; Stderr=@() }
    }catch{
        # Gather what was written before failure + location info
        $stdoutText=$sw.ToString()
        $stdoutLines=@(); if($stdoutText){ $stdoutLines=@($stdoutText -split "`r?`n") }
        $msg=$_.Exception.Message
        $pos=$_.InvocationInfo | ForEach-Object { $_.PositionMessage }
        if($pos){ $stderrBuf.Add($pos) | Out-Null }
        Write-CustomLog ("Start-FromCurrentUserStdin: runtime error: " + $msg)
        return @{ Success=$false; ExitCode=1; Process_Id=$PID; Error=("Runtime error: " + $msg); Stdout=$stdoutLines; Stderr=@($stderrBuf.ToArray()) }
    }finally{
        try{ [Console]::SetOut($oldOut) }catch{}
        try{ $sw.Dispose() }catch{}
        $ErrorActionPreference=$oldEAP
    }
}

function Start-FromSystemAsCurrentUser {
    <#
      Launch PowerShell in the interactive user's session (SYSTEM caller), feed our script via STDIN,
      and drain child's STDOUT/STDERR line-by-line here (no external Initialize-ReadSTD).
      Returns: @{ Success=[bool]; ExitCode=[int]; Process_Id=[int|null]; Error=[string|null]; Stdout=[string[]]; Stderr=[string[]] }
    #>
    param(
        [Parameter(Mandatory=$true)][int]$SessionId,
        [Parameter(Mandatory=$true)][string]$pwsh,
        [Parameter(Mandatory=$true)][string]$Script,
        [Parameter(Mandatory=$false)][switch]$ShowWindow,
        [Parameter(Mandatory=$false)][int]$TimeoutSeconds = 600,
        [Parameter(Mandatory=$false)][string]$WorkingDir = $(Split-Path -Path $pwsh -Parent)
    )
    function Enable-Privilege([string]$PrivilegeName){
        $TOKEN_ADJUST_PRIVILEGES=0x20; $TOKEN_QUERY=0x8; $SE_PRIVILEGE_ENABLED=0x2
        $currentProcessHandle=[Win32Api]::GetCurrentProcess()
        $processTokenHandle=[IntPtr]::Zero
        if(-not [AdvApi32]::OpenProcessToken($currentProcessHandle,($TOKEN_ADJUST_PRIVILEGES -bor $TOKEN_QUERY),[ref]$processTokenHandle)){return $false}
        try{
            $luid=New-Object LUID
            if(-not [AdvApi32]::LookupPrivilegeValue($null,$PrivilegeName,[ref]$luid)){return $false}
            $luidAndAttributes=New-Object LUID_AND_ATTRIBUTES
            $luidAndAttributes.Luid=$luid; $luidAndAttributes.Attributes=$SE_PRIVILEGE_ENABLED
            $tokenPrivileges=New-Object TOKEN_PRIVILEGES
            $tokenPrivileges.PrivilegeCount=1; $tokenPrivileges.Privileges=$luidAndAttributes
            [AdvApi32]::AdjustTokenPrivileges($processTokenHandle,$false,[ref]$tokenPrivileges,0,[IntPtr]::Zero,[IntPtr]::Zero)|Out-Null
            return $true
        } finally { if($processTokenHandle -ne [IntPtr]::Zero){[Win32Api]::CloseHandle($processTokenHandle)|Out-Null} }
    }
    Write-CustomLog ("Start-FromSystemAsCurrentUser: SessionId={0} Pwsh='{1}' ShowWindow={2} Timeout={3}s WorkingDir='{4}'" -f $SessionId,$pwsh,[bool]$ShowWindow,$TimeoutSeconds,$WorkingDir)
    # Encode the script for a robust stdin bootstrap (same as non-SYSTEM path).
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        $commandLine  = '[Console]::InputEncoding=[Text.Encoding]::UTF8; $sb=[ScriptBlock]::Create([Console]::In.ReadToEnd()); & $sb'
        $argumentLine   = "-NoLogo -NoProfile -Sta -ExecutionPolicy Bypass -Command ""$commandLine"""
        $scriptToSend   = $Script   # keep accents
    } else {
        # Old powershell -> avoid accents (ASCII-only script)
        $noAccents = $Script
        $accentMap = @(
            @('à','a'),@('â','a'),@('ä','a'),@('é','e'),@('è','e'),@('ê','e'),@('ë','e'),@('î','i'),@('ï','i'),@('ô','o'),@('ö','o'),@('ù','u'),@('û','u'),@('ü','u'),@('ç','c'),
            @('À','A'),@('Â','A'),@('Ä','A'),@('É','E'),@('È','E'),@('Ê','E'),@('Ë','E'),@('Î','I'),@('Ï','I'),@('Ô','O'),@('Ö','O'),@('Ù','U'),@('Û','U'),@('Ü','U'),@('Ç','C')
        )
        foreach ($pair in $accentMap) { $noAccents = $noAccents -replace [Regex]::Escape($pair[0]), $pair[1] }
            $argumentLine   = '-NoLogo -NoProfile -Sta -ExecutionPolicy Bypass -'
            $scriptToSend   = $noAccents
    }
    # Enable required privileges
    [void](Enable-Privilege "SeIncreaseQuotaPrivilege")
    [void](Enable-Privilege "SeAssignPrimaryTokenPrivilege")
    # Obtain a primary token for the interactive session.
    $userTokenHandle=[IntPtr]::Zero; $primaryTokenHandle=[IntPtr]::Zero
    if(-not [WtsApi32]::WTSQueryUserToken($SessionId,[ref]$userTokenHandle)){
        Write-CustomLog "Start-FromSystemAsCurrentUser: WTSQueryUserToken failed"
        return @{ Success=$false; ExitCode=7; Process_Id=$null; Error="WTSQueryUserToken failed (SessionId=$SessionId)"; Stdout=@(); Stderr=@() }
    }
    $TOKEN_ALL_ACCESS=0xF01FF; $SECURITY_IMPERSONATION=2; $TOKEN_TYPE_PRIMARY=1
    if(-not [AdvApi32]::DuplicateTokenEx($userTokenHandle,$TOKEN_ALL_ACCESS,[IntPtr]::Zero,$SECURITY_IMPERSONATION,$TOKEN_TYPE_PRIMARY,[ref]$primaryTokenHandle)){
        [Win32Api]::CloseHandle($userTokenHandle)|Out-Null
        Write-CustomLog "Start-FromSystemAsCurrentUser: DuplicateTokenEx failed"
        return @{ Success=$false; ExitCode=8; Process_Id=$null; Error="DuplicateTokenEx failed"; Stdout=@(); Stderr=@() }
    }
    # Create three anonymous pipes for child's STDIN/STDOUT/STDERR.
    $securityAttributes = New-Object Win32Api+SECURITY_ATTRIBUTES
    $securityAttributes.nLength=[Runtime.InteropServices.Marshal]::SizeOf([type]([Win32Api+SECURITY_ATTRIBUTES])); $securityAttributes.bInheritHandle=$true
    $stdinReadHandle=[IntPtr]::Zero;  $stdinWriteHandle=[IntPtr]::Zero
    $stdoutReadHandle=[IntPtr]::Zero; $stdoutWriteHandle=[IntPtr]::Zero
    $stderrReadHandle=[IntPtr]::Zero; $stderrWriteHandle=[IntPtr]::Zero
    if(-not [Win32Api]::CreatePipe([ref]$stdinReadHandle,[ref]$stdinWriteHandle,[ref]$securityAttributes,0)){
        Write-CustomLog "CreatePipe(STDIN) failed"
        [Win32Api]::CloseHandle($primaryTokenHandle)|Out-Null; [Win32Api]::CloseHandle($userTokenHandle)|Out-Null
        return @{ Success=$false; ExitCode=5; Process_Id=$null; Error="CreatePipe(STDIN) failed"; Stdout=@(); Stderr=@() }
    }
    [void][Win32Api]::SetHandleInformation($stdinWriteHandle,[Win32Api]::HANDLE_FLAG_INHERIT,0)
    if(-not [Win32Api]::CreatePipe([ref]$stdoutReadHandle,[ref]$stdoutWriteHandle,[ref]$securityAttributes,0)){
        Write-CustomLog "CreatePipe(STDOUT) failed"
        [Win32Api]::CloseHandle($stdinReadHandle)|Out-Null; [Win32Api]::CloseHandle($stdinWriteHandle)|Out-Null
        [Win32Api]::CloseHandle($primaryTokenHandle)|Out-Null; [Win32Api]::CloseHandle($userTokenHandle)|Out-Null
        return @{ Success=$false; ExitCode=5; Process_Id=$null; Error="CreatePipe(STDOUT) failed"; Stdout=@(); Stderr=@() }
    }
    [void][Win32Api]::SetHandleInformation($stdoutReadHandle,[Win32Api]::HANDLE_FLAG_INHERIT,0)
    if(-not [Win32Api]::CreatePipe([ref]$stderrReadHandle,[ref]$stderrWriteHandle,[ref]$securityAttributes,0)){
        Write-CustomLog "CreatePipe(STDERR) failed"
        [Win32Api]::CloseHandle($stdoutReadHandle)|Out-Null; [Win32Api]::CloseHandle($stdoutWriteHandle)|Out-Null
        [Win32Api]::CloseHandle($stdinReadHandle)|Out-Null;  [Win32Api]::CloseHandle($stdinWriteHandle)|Out-Null
        [Win32Api]::CloseHandle($primaryTokenHandle)|Out-Null; [Win32Api]::CloseHandle($userTokenHandle)|Out-Null
        return @{ Success=$false; ExitCode=5; Process_Id=$null; Error="CreatePipe(STDERR) failed"; Stdout=@(); Stderr=@() }
    }
    [void][Win32Api]::SetHandleInformation($stderrReadHandle,[Win32Api]::HANDLE_FLAG_INHERIT,0)
    # Configure STARTUPINFO for redirected std handles; set desktop for UI session.
    $startupInfo=New-Object STARTUPINFO
    $startupInfo.cb=[Runtime.InteropServices.Marshal]::SizeOf([type]([STARTUPINFO]))
    $startupInfo.lpDesktop='winsta0\default'
    $startupInfo.dwFlags=0x100
    $startupInfo.hStdInput=$stdinReadHandle
    $startupInfo.hStdOutput=$stdoutWriteHandle
    $startupInfo.hStdError=$stderrWriteHandle
    if($ShowWindow){ $startupInfo.dwFlags=$startupInfo.dwFlags -bor 0x1; $startupInfo.wShowWindow=1 }
    # Creation flags: hidden vs new console + breakaway from parent job.
    $CREATE_NO_WINDOW=0x08000000; $CREATE_NEW_CONSOLE=0x00000010; $CREATE_BREAKAWAY_FROM_JOB=0x01000000
    $creationFlags = ($(if($ShowWindow){$CREATE_NEW_CONSOLE}else{$CREATE_NO_WINDOW})) -bor $CREATE_BREAKAWAY_FROM_JOB
    # Launch PowerShell in the target session using the primary token.
    $processInformation=New-Object PROCESS_INFORMATION
    Write-CustomLog ("Start-FromSystemAsCurrentUser: launching '{0}' with args='{1}'" -f $pwsh,$argumentLine)
    if(-not [AdvApi32]::CreateProcessAsUser($primaryTokenHandle,$pwsh,$argumentLine,[IntPtr]::Zero,[IntPtr]::Zero,$true,$creationFlags,[IntPtr]::Zero,$WorkingDir,[ref]$startupInfo,[ref]$processInformation)){
        $lastError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-CustomLog ("Start-FromSystemAsCurrentUser: CreateProcessAsUser failed {0}" -f $lastError)
        foreach($h in $stderrReadHandle,$stderrWriteHandle,$stdoutReadHandle,$stdoutWriteHandle,$stdinReadHandle,$stdinWriteHandle,$primaryTokenHandle,$userTokenHandle){ if($h -ne [IntPtr]::Zero){try{[Win32Api]::CloseHandle($h)|Out-Null}catch{}} }
        return @{ Success=$false; ExitCode=4; Process_Id=$null; Error=("CreateProcessAsUser failed (error="+$lastError+")"); Stdout=@(); Stderr=@() }
    }
    # Child process handles/ids; close thread handle and non-needed pipe ends on our side.
    if($processInformation.hThread -ne [IntPtr]::Zero){[Win32Api]::CloseHandle($processInformation.hThread)|Out-Null}
    if($stdinReadHandle -ne [IntPtr]::Zero){[Win32Api]::CloseHandle($stdinReadHandle)|Out-Null; $stdinReadHandle=[IntPtr]::Zero}
    if($stdoutWriteHandle -ne [IntPtr]::Zero){[Win32Api]::CloseHandle($stdoutWriteHandle)|Out-Null; $stdoutWriteHandle=[IntPtr]::Zero}
    if($stderrWriteHandle -ne [IntPtr]::Zero){[Win32Api]::CloseHandle($stderrWriteHandle)|Out-Null; $stderrWriteHandle=[IntPtr]::Zero}
    $childProcessHandle=$processInformation.hProcess
    $childProcessId=$processInformation.dwProcessId
    Write-CustomLog ("Start-FromSystemAsCurrentUser: child PID={0}" -f $childProcessId)
    # Wrap our read ends into FileStreams (async=false; we do our own buffering).
    $stdoutSafeReadHandle=New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($stdoutReadHandle,$false)
    $stderrSafeReadHandle=New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($stderrReadHandle,$false)
    $stdoutFileStream=New-Object System.IO.FileStream($stdoutSafeReadHandle,[System.IO.FileAccess]::Read,8192,$false)
    $stderrFileStream=New-Object System.IO.FileStream($stderrSafeReadHandle,[System.IO.FileAccess]::Read,8192,$false)
    # Start background drainers (runspaces) that read UTF-8 (no BOM) line-by-line until EOF.
    $stdoutReader=$null; $stderrReader=$null
    try {
        function New-Drainer {
            param(
                [string]$TagPrefix,
                [System.IO.FileStream]$FileStream,
                [int]$ChildPid
            )
            $lines = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
            $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace(); $runspace.Open()
            $runspace.SessionStateProxy.SetVariable('FS',$FileStream)
            $runspace.SessionStateProxy.SetVariable('Lines',$lines)
            $runspace.SessionStateProxy.SetVariable('Tag',("{0}{1}" -f $TagPrefix,$ChildPid))
            $runspace.SessionStateProxy.SetVariable('LogEveryN',200)
            $ps = [System.Management.Automation.PowerShell]::Create(); $ps.Runspace=$runspace
            [void]$ps.AddScript({
                try{ Write-CustomLog ("[Reader:{0}] Starting." -f $Tag) }catch{}
                $sr=$null; $count=0; $tick=[Environment]::TickCount
                try{
                    $sr=New-Object System.IO.StreamReader($FS,(New-Object System.Text.UTF8Encoding($false)),$true,4096)
                    $line=$null
                    while($null -ne ($line=$sr.ReadLine())){
                        [void]$Lines.Add($line); $count++
                        if(($count%$LogEveryN)-eq 0){
                            try{Write-CustomLog ("[Reader:{0}] Drained {1} lines (elapsed {2} ms)" -f $Tag,$count,([Environment]::TickCount-$tick))}catch{}
                        }
                    }
                    $rem=$sr.ReadToEnd(); if($rem){ [void]$Lines.Add($rem); $count++ }
                    try{ Write-CustomLog ("[Reader:{0}] EOF. TotalLines={1}" -f $Tag,$count) }catch{}
                } catch { try{ Write-CustomLog ("[Reader:{0}] Loop failed: {1}" -f $Tag,$_.Exception.Message) }catch{} }
                finally {
                    try{ if($sr){ $sr.Dispose() } }catch{ try{Write-CustomLog ("[Reader:{0}] Dispose failed: {1}" -f $Tag,$_.Exception.Message)}catch{} }
                    try{ Write-CustomLog ("[Reader:{0}] Finished." -f $Tag) }catch{}
                }
            })
            $async = $ps.BeginInvoke()
            return @{ Runspace=$runspace; PowerShell=$ps; AsyncResult=$async; Lines=$lines }
        }
        $stdoutReader = New-Drainer -TagPrefix "PID{0}-StdOutPipe" -FileStream $stdoutFileStream -ChildPid $childProcessId
        $stderrReader = New-Drainer -TagPrefix "PID{0}-StdErrPipe" -FileStream $stderrFileStream -ChildPid $childProcessId
        Write-CustomLog "Start-FromSystemAsCurrentUser: readers initialized"
    }
    catch {
        Write-CustomLog ("Start-FromSystemAsCurrentUser: reader init failed: " + $_.Exception.Message)
        try{ [Win32Api]::TerminateProcess($childProcessHandle,11) | Out-Null }catch{}
        foreach($h in $stdoutReadHandle,$stderrReadHandle,$primaryTokenHandle,$userTokenHandle,$childProcessHandle){
            if($h -ne [IntPtr]::Zero){ try{[Win32Api]::CloseHandle($h)|Out-Null}catch{} }
        }
        return @{
            Success=$false; ExitCode=11; Process_Id=$childProcessId;
            Error=("Reader initialization failed: " + $_.Exception.Message);
            Stdout=@(); Stderr=@()
        }
    }
    # Write UTF-8 (no BOM) preamble + script to child's STDIN, then signal EOF.
    try{
        $stdinSafeWriteHandle=New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($stdinWriteHandle,$true)
        $stdinStream=New-Object System.IO.FileStream($stdinSafeWriteHandle,[System.IO.FileAccess]::Write,4096,$false)
        $stdinWriter=New-Object System.IO.StreamWriter($stdinStream,(New-Object System.Text.UTF8Encoding($false)))
        $stdinWriter.NewLine="`n"; $stdinWriter.AutoFlush=$true
        $encodingPreamble=@'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding  = New-Object System.Text.UTF8Encoding($false)
try { $script:__isPSCore = $PSVersionTable.PSEdition -eq 'Core' } catch { $script:__isPSCore = $false }
if (-not $script:__isPSCore) { try { $OutputEncoding = [Console]::OutputEncoding } catch {} }
'@ + "`n"
        $utf8NoBom=New-Object System.Text.UTF8Encoding($false)
        $bytesLen=($utf8NoBom.GetByteCount($encodingPreamble)+$utf8NoBom.GetByteCount($scriptToSend))
        Write-CustomLog ("Start-FromSystemAsCurrentUser: writing {0} bytes to child's STDIN" -f $bytesLen)
        $stdinWriter.Write($encodingPreamble)
        $stdinWriter.Write($scriptToSend)
        $stdinWriter.Dispose()
        $stdinWriteHandle=[IntPtr]::Zero
        Write-CustomLog "Start-FromSystemAsCurrentUser: STDIN closed (EOF signaled)"
    } catch {
        Write-CustomLog ("Start-FromSystemAsCurrentUser: failed to write STDIN: " + $_.Exception.Message)
        try{ [Win32Api]::TerminateProcess($childProcessHandle,5) | Out-Null }catch{}
        try{ if($stdoutReader){ $stdoutReader.PowerShell.EndInvoke($stdoutReader.AsyncResult) } }catch{}
        try{ if($stderrReader){ $stderrReader.PowerShell.EndInvoke($stderrReader.AsyncResult) } }catch{}
        try{ if($stdoutReader){ $stdoutReader.PowerShell.Dispose(); $stdoutReader.Runspace.Close() } }catch{}
        try{ if($stderrReader){ $stderrReader.PowerShell.Dispose(); $stderrReader.Runspace.Close() } }catch{}
        foreach($h in $stdoutReadHandle,$stderrReadHandle,$primaryTokenHandle,$userTokenHandle,$childProcessHandle){ if($h -ne [IntPtr]::Zero){ try{[Win32Api]::CloseHandle($h)|Out-Null}catch{} } }
        return @{ Success=$false; ExitCode=5; Process_Id=$childProcessId; Error=("Failed to write to child STDIN: " + $_.Exception.Message); Stdout=@($stdoutReader.Lines.ToArray()); Stderr=@($stderrReader.Lines.ToArray()) }
    }
    # Wait for both drainers to reach EOF with an overall timeout; then collect exit code.
    $timeoutMilliseconds=[int]([Math]::Max(1,$TimeoutSeconds)*1000)
    $deadline=[DateTime]::UtcNow.AddMilliseconds($timeoutMilliseconds)
    Write-CustomLog ("Start-FromSystemAsCurrentUser: waiting up to {0} ms for readers to reach EOF" -f $timeoutMilliseconds)
    $stdoutDone=$false; $stderrDone=$false
    try{
        $remaining=[int]([Math]::Max(1,($deadline-[DateTime]::UtcNow).TotalMilliseconds))
        $stdoutDone=$stdoutReader.AsyncResult.AsyncWaitHandle.WaitOne($remaining)
        $remaining=[int]([Math]::Max(1,($deadline-[DateTime]::UtcNow).TotalMilliseconds))
        $stderrDone=$stderrReader.AsyncResult.AsyncWaitHandle.WaitOne($remaining)
    } catch {}
    if(-not ($stdoutDone -and $stderrDone)){
        Write-CustomLog ("Start-FromSystemAsCurrentUser: timeout (StdOutDone={0} StdErrDone={1}); terminating child" -f $stdoutDone,$stderrDone)
        try{ [Win32Api]::TerminateProcess($childProcessHandle,3) | Out-Null }catch{}
        try{ $stdoutReader.PowerShell.EndInvoke($stdoutReader.AsyncResult) }catch{}
        try{ $stderrReader.PowerShell.EndInvoke($stderrReader.AsyncResult) }catch{}
        try{ $stdoutReader.PowerShell.Dispose(); $stdoutReader.Runspace.Close() }catch{}
        try{ $stderrReader.PowerShell.Dispose(); $stderrReader.Runspace.Close() }catch{}
        foreach($h in $stdoutReadHandle,$stderrReadHandle,$primaryTokenHandle,$userTokenHandle,$childProcessHandle){ if($h -ne [IntPtr]::Zero){ try{[Win32Api]::CloseHandle($h)|Out-Null}catch{} } }
        return @{ Success=$false; ExitCode=3; Process_Id=$childProcessId; Error=("Timeout after ${TimeoutSeconds}s"); Stdout=@($stdoutReader.Lines.ToArray()); Stderr=@($stderrReader.Lines.ToArray()) }
    }
    # Finish drainers and clean runspaces.
    try{ $null=$stdoutReader.PowerShell.EndInvoke($stdoutReader.AsyncResult) }catch{}
    try{ $null=$stderrReader.PowerShell.EndInvoke($stderrReader.AsyncResult) }catch{}
    try{ $stdoutReader.PowerShell.Dispose(); $stdoutReader.Runspace.Close() }catch{}
    try{ $stderrReader.PowerShell.Dispose(); $stderrReader.Runspace.Close() }catch{}
    # Obtain child's exit code.
    $exitCodeValue=0; $gotExit=$false
    try{ $gotExit=[Win32Api]::GetExitCodeProcess($childProcessHandle,[ref]$exitCodeValue) }catch{ $gotExit=$false }
    # Snapshot collected output.
    $stdoutLines=@(); $stderrLines=@()
    try{ $stdoutLines=@($stdoutReader.Lines.ToArray()) }catch{}
    try{ $stderrLines=@($stderrReader.Lines.ToArray()) }catch{}
    Write-CustomLog ("Start-FromSystemAsCurrentUser: ExitCode={0} StdOutLines={1} StdErrLines={2}" -f $exitCodeValue,$stdoutLines.Count,$stderrLines.Count)
    # Close remaining handles.
    foreach($h in $stdoutReadHandle,$stderrReadHandle,$primaryTokenHandle,$userTokenHandle,$childProcessHandle){ if($h -ne [IntPtr]::Zero){ try{[Win32Api]::CloseHandle($h)|Out-Null}catch{} } }
    if($gotExit){
        return @{ Success=($exitCodeValue -eq 0); ExitCode=$exitCodeValue; Process_Id=$childProcessId; Error=$null; Stdout=$stdoutLines; Stderr=$stderrLines }
    } else {
        return @{ Success=$false; ExitCode=12; Process_Id=$childProcessId; Error="ExitCode unavailable"; Stdout=$stdoutLines; Stderr=$stderrLines }
    }
}


# ==================================================================
#                           Popup SCRIPT
# ==================================================================

function Merge-PopupScript($PopupTitle, $Log, $detectedProcesses, $Timer) {

    function Format-PSLiteral([string]$s){
        if($null -eq $s){ return "" }
        # In a string between single quotes, only ' must be doubled.
        return ($s -replace "'","''")
    }

    $Log     = Format-PSLiteral $Log
    $PopupTitle = Format-PSLiteral $PopupTitle
    $Timer   = [int]$Timer
    # Builds the lines of a PS literal table: @( @{...}; @{...} )
    $itemsSb = New-Object Text.StringBuilder
    for($i=0; $i -lt $detectedProcesses.Count; $i++){
        $item = $detectedProcesses[$i]
        $name = Format-PSLiteral $item.Name
        $exe  = Format-PSLiteral $item.ExePath
        $desc = Format-PSLiteral $item.Description
        $icon = Format-PSLiteral $item.IconBase64
        if($i -gt 0){ [void]$itemsSb.AppendLine(",") }
        [void]$itemsSb.Append("    @{ Name='$name'; ExePath='$exe'; Description='$desc'; IconBase64='$icon' }")
    }
    $psItems = $itemsSb.ToString()

    $PopupScript = @"
`$Log = '$Log'
`$PopupTitle = '$PopupTitle'
`$detectedProcesses = @(
$psItems
)
`$Timer   = "$(if ($Timer) { $Timer } else { 600 })"

# ----- Optional sidebar logo base64 (will be rotated 90° left) -----
[string]`$SidebarLogoBase64 = ""

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

# ------------------------- Logging -------------------------
function Write-CustomLog {
    param([string]`$Message)
    `$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    `$line = "`$ts - [Popup] - `$Message"
    try {
        `$streamWriter = New-Object IO.StreamWriter(`$Log,`$true,[Text.Encoding]::UTF8)
        `$streamWriter.WriteLine(`$line)
    } catch {} finally { if (`$streamWriter){`$streamWriter.Close()} }
    Write-Host `$line
}
Write-CustomLog "=== Popup starting ==="

trap {
    try   {Write-CustomLog "UNHANDLED ERROR: `$(`$_.Exception.Message)"}
    catch {Write-Host        "UNHANDLED ERROR: `$(`$_.Exception.Message)"}
    continue
}

function Get-DisplayPrimaryScaling {
    `$major = [Environment]::OSVersion.Version.Major
    if (`$major -lt 6) {
        try {
            `$val = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontDPI' -ErrorAction Stop
            if (`$val -and `$val.LogPixels -is [int] -and `$val.LogPixels -gt 0) {
                return [math]::Round(`$val.LogPixels / 96.0, 2)
            }
        } catch { return 1.0 }
    }
    else {
        if (-not ('DPIHelper1' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Drawing;
public static class DPIHelper1 {
    [DllImport("gdi32.dll")] static extern int GetDeviceCaps(IntPtr hdc, int nIndex);
    public enum DeviceCap { VERTRES = 10, DESKTOPVERTRES = 117, LOGPIXELSX = 88 }
    public static float GetScaling() {
        using (Graphics g = Graphics.FromHwnd(IntPtr.Zero)) {
            IntPtr hdc = g.GetHdc();
            try {
                int logical  = GetDeviceCaps(hdc, (int)DeviceCap.VERTRES);
                int physical = GetDeviceCaps(hdc, (int)DeviceCap.DESKTOPVERTRES);
                if (logical > 0 && physical > 0)  { return (float)physical / (float)logical; }
                int dpi = GetDeviceCaps(hdc, (int)DeviceCap.LOGPIXELSX);
                return (float)dpi / 96.0f;
            } finally { g.ReleaseHdc(hdc); }
        }
    }
}
'@ -ReferencedAssemblies System.Drawing.dll
        }
    return [DPIHelper1]::GetScaling()
    }
}
`$DPI_Factor = Get-DisplayPrimaryScaling
Write-CustomLog "DPI = `$DPI_Factor "

`$decodedList = @()
foreach (`$item in `$detectedProcesses) {
    `$imgObj = `$null
    if (`$item.IconBase64) {
        try {
            `$bytes = [Convert]::FromBase64String(`$item.IconBase64)
            `$ms    = New-Object System.IO.MemoryStream(, `$bytes)
            `$img   = [System.Drawing.Image]::FromStream(`$ms)
            # Clone to a standalone Bitmap so we can dispose the stream safely afterward
            `$bmp = New-Object System.Drawing.Bitmap `$img
            `$img.Dispose()
            `$ms.Dispose()
            `$imgObj = `$bmp
        } catch {
            # fallback to a generic application bitmap
            try { `$imgObj = [System.Drawing.SystemIcons]::Application.ToBitmap() } 
            catch { `$imgObj = `$null }
        }
    } else {
        try { `$imgObj = [System.Drawing.SystemIcons]::Application.ToBitmap() } 
        catch { `$imgObj = `$null }
    }
    `$decodedList += ,@{
        Name        = `$item.Name
        ExePath     = `$item.ExePath
        Description = `$item.Description
        Icon        = `$imgObj
    }
}
`$detectedProcesses = `$decodedList
Write-CustomLog "detectedProcesses built, count=`$(`$detectedProcesses.Count)"

# ----- Native helpers (DPI + regions + drag) -----
if (-not ('Win32Native' -as [type])) {
    Add-Type -ReferencedAssemblies System.Drawing,System.Windows.Forms -TypeDefinition @'
using System;
using System.Windows.Forms;
using System.Runtime.InteropServices;
public static class DPIHelper2 {
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
public static class Win32Native {
    [DllImport("gdi32.dll", SetLastError=true)]
    public static extern IntPtr CreateRoundRectRgn(int nLeftRect,int nTopRect,int nRightRect,int nBottomRect,int nWidthEllipse,int nHeightEllipse);
    [DllImport("user32.dll", SetLastError=true)]
    public static extern int SetWindowRgn(IntPtr hWnd, IntPtr hRgn, bool bRedraw);
    [DllImport("user32.dll")] public static extern bool ReleaseCapture();
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
}
public class Win32MsgHelper : NativeWindow {
    private Form _form;
    public Win32MsgHelper(Form form) { _form = form; this.AssignHandle(form.Handle); }
    public event EventHandler DragFinished;
    protected override void WndProc(ref Message m) {
        base.WndProc(ref m);
        const int WM_EXITSIZEMOVE = 0x232;
        if (m.Msg == WM_EXITSIZEMOVE && DragFinished != null) DragFinished(_form, EventArgs.Empty);
    }
}
public class TransparentPictureBox : PictureBox {
    protected override void WndProc(ref Message m) {
        const int WM_NCHITTEST = 0x84;
        if (m.Msg == WM_NCHITTEST) {
            m.Result = (IntPtr)(-1); // ignore mouse hit, pass to parent
            return;
        }
        base.WndProc(ref m);
    }
}
public class NoFocusButton : Button { public NoFocusButton(){ this.SetStyle(ControlStyles.Selectable,false);} public void DisableFocus(){} }
'@
}
Write-CustomLog "Assemblies Loaded"

try { [DPIHelper2]::SetProcessDPIAware() | Out-Null ; Write-CustomLog "DPI Aware set." } 
catch { Write-CustomLog "Cannot set DPI aware on this system." }

# ----- Localization -----
`$IsFrenchUI = `$false
try { `$IsFrenchUI = ([System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName -eq 'fr') } catch { `$IsFrenchUI = `$false }
`$TextResources = @{
    fr = @{ InstallingOf="Installation de "; DefaultInfo="Veuillez sauvegarder votre travail avant de continuer car les applications suivantes seront fermées automatiquement."; CountdownLabel="Compte à rebours avant fermeture automatique"; ActionButton="Fermer les applications et installer"; HourSuffix="h"; MinSuffix="m"; SecSuffix="s" }
    en = @{ InstallingOf="Installing "; DefaultInfo="Please save your work before continuing because the applications below will be closed automatically."; CountdownLabel="Countdown before automatic closing"; ActionButton="Close apps and install"; HourSuffix="h"; MinSuffix="m"; SecSuffix="s" }
}
`$Locale = if (`$IsFrenchUI) { `$TextResources.fr } else { `$TextResources.en }

# ----- helpers -----
function New-FontObject([string]`$Family,[float]`$Size,[System.Drawing.FontStyle]`$Style) { New-Object System.Drawing.Font(`$Family,`$Size,`$Style,[System.Drawing.GraphicsUnit]::Point) }
function Set-ControlRoundRegion(`$Control,[int]`$Radius) {
    if (-not `$Control -or `$Control.IsDisposed) { return }
    if (`$Control.Width -le 0 -or `$Control.Height -le 0) { return }
    try { `$h = [Win32Native]::CreateRoundRectRgn(0,0,`$Control.Width,`$Control.Height,`$Radius,`$Radius); [Win32Native]::SetWindowRgn(`$Control.Handle,`$h,`$true) | Out-Null } catch {}
}
function Format-TimeString([int]`$TotalSeconds,[Hashtable]`$Loc) {
    if (`$TotalSeconds -lt 0) { `$TotalSeconds = 0 }
    `$h = [int]([math]::Floor(`$TotalSeconds/3600)); `$m = [int]([math]::Floor((`$TotalSeconds%3600)/60)); `$s = [int](`$TotalSeconds%60)
    if (`$h -gt 0) { return ("{0}{3} {1}{4} {2}{5}" -f `$h,`$m,`$s,`$Loc.HourSuffix,`$Loc.MinSuffix,`$Loc.SecSuffix) }
    elseif (`$m -gt 0) { return ("{0}{2} {1}{3}" -f `$m,`$s,`$Loc.MinSuffix,`$Loc.SecSuffix) }
    else { return ("{0}{1}" -f `$s,`$Loc.SecSuffix) }
}

# ----- Colors, fonts, spacing -----
`$ColorBlack          = [System.Drawing.Color]::FromArgb(0,0,0)
`$ColorBlue1          = [System.Drawing.Color]::FromArgb(0,80,200)
`$ColorBlue2          = [System.Drawing.Color]::FromArgb(0, 80, 250)
`$ColorMainBackground = [System.Drawing.Color]::FromArgb(235,240,255)
`$ColorCardBorder     = [System.Drawing.Color]::FromArgb(210,215,220)
`$ColorTextMain       = [System.Drawing.Color]::FromArgb(45,45,60)
`$ColorRed            = [System.Drawing.Color]::FromArgb(180,0,0)

`$FontBase            = New-FontObject "Arial"    10 ([System.Drawing.FontStyle]::Regular)
`$FontHeader          = New-FontObject "Arial"    18 ([System.Drawing.FontStyle]::Bold)
`$FontText            = New-FontObject "Arial"    11 ([System.Drawing.FontStyle]::Regular)
`$FontTextBold        = New-FontObject "Arial"    12 ([System.Drawing.FontStyle]::Bold)
`$FontTextBoldUI      = New-FontObject "Segoe UI" 11 ([System.Drawing.FontStyle]::Bold)
`$FontSmall           = New-FontObject "Arial"    9  ([System.Drawing.FontStyle]::Regular)

`$cardHeight               = 48

# ----- Root form -----
`$MainForm = New-Object System.Windows.Forms.Form
`$MainForm.SuspendLayout()
`$MainForm.AutoScaleDimensions = New-Object System.Drawing.SizeF(96,96)
`$MainForm.AutoScaleMode = 'Dpi'
`$MainForm.StartPosition = 'Manual'
`$MainForm.FormBorderStyle = 'None'
`$MainForm.ShowInTaskbar = `$false
`$MainForm.TopMost = `$true
`$MainForm.BackColor = `$ColorMainBackground
`$MainForm.Font = `$FontBase
`$MainForm.ClientSize = New-Object System.Drawing.Size(600,284)

# Layout root (sidebar + main area)
`$RootLayout = New-Object System.Windows.Forms.TableLayoutPanel
`$RootLayout.Dock = 'Fill'; `$RootLayout.ColumnCount=2; `$RootLayout.RowCount=1
`$SbW = if (`$SidebarLogoBase64) {12} else {4}
`$null = `$RootLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent,`$SbW))) # Left SideBar
`$null = `$RootLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent,88)))    # Main column
`$null = `$RootLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent,100)))         # Main row

`$SidebarPanel = New-Object System.Windows.Forms.Panel
`$SidebarPanel.Dock = 'Fill' ; `$SidebarPanel.BackColor = `$ColorBlue1
`$SidebarPanel.Margin = [System.Windows.Forms.Padding]::Empty           ; `$SidebarPanel.Padding = New-Object System.Windows.Forms.Padding(10,0,10,0)
`$SidebarPanel.add_MouseEnter({ `$SidebarPanel.BackColor = `$ColorBlue2 ; `$SidebarPanel.Cursor = [System.Windows.Forms.Cursors]::SizeAll })
`$SidebarPanel.add_MouseLeave({ `$SidebarPanel.BackColor = `$ColorBlue1 ; `$SidebarPanel.Cursor = [System.Windows.Forms.Cursors]::Default })

`$MainPanel = New-Object System.Windows.Forms.Panel
`$MainPanel.Dock='Fill'; `$MainPanel.BackColor=`$ColorMainBackground
`$MainPanel.Padding=New-Object System.Windows.Forms.Padding(12,0,12,0)

`$RootLayout.Controls.Add(`$SidebarPanel,0,0)
`$RootLayout.Controls.Add(`$MainPanel,1,0)

# Main content layout
`$MainContent = New-Object System.Windows.Forms.TableLayoutPanel
`$MainContent.Dock='Fill'; `$MainContent.ColumnCount=1; `$MainContent.RowCount=5
`$null = `$MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,63)))  # Title
`$null = `$MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,155))) # Central zone
`$null = `$MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,14)))  # Spacer
`$null = `$MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,28)))  # Button zone
`$null = `$MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,12)))  # Spacer
`$MainPanel.Controls.Add(`$MainContent)

# Header label
`$HeaderLabel = New-Object System.Windows.Forms.Label
`$HeaderLabel.ForeColor = `$ColorTextMain
`$HeaderLabel.Font = `$FontHeader
`$HeaderLabel.AutoSize = `$false
`$HeaderLabel.Dock = 'Fill'
`$HeaderLabel.TextAlign = 'MiddleLeft'
function Set-HeaderLabelHeight([System.Windows.Forms.Label]`$label,[string]`$prefix,[string]`$PopupTitle) {
    `$maxSize = `$label.ClientSize
    if (`$maxSize.Width -le 0) { `$maxSize = New-Object System.Drawing.Size(580,63) } # fallback
    `$stringFormat = New-Object System.Drawing.StringFormat
    `$stringFormat.FormatFlags = [System.Drawing.StringFormatFlags]::LineLimit
    `$stringFormat.Trimming    = [System.Drawing.StringTrimming]::EllipsisWord
    `$graphics = [System.Drawing.Graphics]::FromHwnd(`$label.Handle)
    try {
        `$fullText   = "`$prefix`$PopupTitle"
        `$measured   = `$graphics.MeasureString(`$fullText,`$label.Font,`$maxSize.Width,`$stringFormat)
        `$lineHeight = `$label.Font.Height
        `$threshold  = [math]::Ceiling(`$lineHeight * 1.5)
        if (`$measured.Height -le `$threshold) {
            `$label.Text = `$fullText
            `$label.AutoEllipsis = `$false
        } else {
            `$twoLines = "`$prefix`r`n`$PopupTitle"
            `$label.Text = `$twoLines
            `$label.AutoEllipsis = `$true
            `$MainContent.RowStyles[0].Height += 7
            `$MainContent.RowStyles[2].Height -= 3
        }
    } finally {
        `$graphics.Dispose()
    }
}

# Card with message + process list + status bar
`$CardBorderPanel = New-Object System.Windows.Forms.Panel
`$CardBorderPanel.Dock='Fill'; `$CardBorderPanel.BackColor=`$ColorCardBorder; `$CardBorderPanel.Padding=New-Object System.Windows.Forms.Padding(1)
`$CardPanel = New-Object System.Windows.Forms.Panel
`$CardPanel.Dock='Fill'; `$CardPanel.BackColor=[System.Drawing.Color]::White; `$CardPanel.Padding=New-Object System.Windows.Forms.Padding(16)
`$CardBorderPanel.Controls.Add(`$CardPanel)

`$CardLayout = New-Object System.Windows.Forms.TableLayoutPanel
`$CardLayout.Dock='Fill'; `$CardLayout.ColumnCount=1; `$CardLayout.RowCount=3
`$null = `$CardLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,46))) # Message
`$null = `$CardLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,28))) # Processes zone
`$null = `$CardLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,45))) # Countdown zone
`$CardPanel.Controls.Add(`$CardLayout)

# Info message (auto-wrap by MaximumSize)
`$InfoLabel = New-Object System.Windows.Forms.Label
`$InfoLabel.AutoSize=`$true; `$InfoLabel.Font=`$FontText; `$InfoLabel.ForeColor=`$ColorTextMain
`$InfoLabel.Text = `$Locale.DefaultInfo 
`$InfoLabel.Dock='Top'; `$InfoLabel.Margin=New-Object System.Windows.Forms.Padding(0,0,0,8)
`$CardLayout.Controls.Add(`$InfoLabel,0,0)
`$AdjustInfoWidth = { `$p=`$InfoLabel.Parent; if (`$p -and -not `$p.IsDisposed) { `$w=[Math]::Max(100,`$p.ClientSize.Width - `$InfoLabel.Margin.Left - `$InfoLabel.Margin.Right); `$InfoLabel.MaximumSize=New-Object System.Drawing.Size(`$w,0) } }
& `$AdjustInfoWidth

# Process zone with border + scroll
`$ProcessBorderPanel = New-Object System.Windows.Forms.Panel
`$ProcessBorderPanel.Dock='Fill'; `$ProcessBorderPanel.BackColor=`$ColorCardBorder; `$ProcessBorderPanel.Padding=New-Object System.Windows.Forms.Padding(1)
`$ProcessScrollPanel = New-Object System.Windows.Forms.Panel
`$ProcessScrollPanel.Dock='Fill'; `$ProcessScrollPanel.BackColor=[System.Drawing.Color]::White; `$ProcessScrollPanel.Padding=New-Object System.Windows.Forms.Padding(10); `$ProcessScrollPanel.AutoScroll=`$true
`$ProcessBorderPanel.Controls.Add(`$ProcessScrollPanel)
`$CardLayout.Controls.Add(`$ProcessBorderPanel,0,1)

`$ProcessFlow = New-Object System.Windows.Forms.FlowLayoutPanel
`$ProcessFlow.Dock='Fill'; `$ProcessFlow.WrapContents=`$false; `$ProcessFlow.FlowDirection='TopDown'; `$ProcessFlow.AutoScroll=`$true; `$ProcessFlow.Padding=New-Object System.Windows.Forms.Padding(0)
`$ProcessScrollPanel.Controls.Add(`$ProcessFlow)

# Status bar (pulse | label | timer)
`$StatusBar = New-Object System.Windows.Forms.TableLayoutPanel
`$StatusBar.Dock='Fill'; `$StatusBar.Height=28; `$StatusBar.BackColor=[System.Drawing.Color]::White
`$StatusBar.Padding=New-Object System.Windows.Forms.Padding(10,0,10,0); `$StatusBar.Margin=New-Object System.Windows.Forms.Padding(0,12,0,0)
`$StatusBar.RowCount=1; `$StatusBar.ColumnCount=3
`$null = `$StatusBar.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))    # Pulse animation
`$null = `$StatusBar.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent,100))) # Countdown label
`$null = `$StatusBar.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))    # Countdown timer
`$null = `$StatusBar.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent,100)))
`$CardLayout.Controls.Add(`$StatusBar,0,2)

`$PulsePictureBox = New-Object Windows.Forms.PictureBox -Property @{ Width=20; Height=20; SizeMode='CenterImage'; Anchor='None' }
`$StatusBar.Controls.Add(`$PulsePictureBox,0,0)
`$CountdownTextLabel = New-Object Windows.Forms.Label -Property @{ AutoSize=`$true; Font=`$FontText; Text=`$Locale.CountdownLabel; ForeColor=`$ColorTextMain; TextAlign='MiddleLeft'; Dock='Left'; Margin=(New-Object Windows.Forms.Padding(6,0,0,0)) }
`$StatusBar.Controls.Add(`$CountdownTextLabel,1,0)
`$CountdownValueLabel = New-Object Windows.Forms.Label -Property @{ AutoSize=`$true; Font=`$FontTextBold; Text=(Format-TimeString `$Timer `$Locale); ForeColor=`$ColorTextMain; TextAlign='MiddleRight'; Dock='Right'; Margin=(New-Object Windows.Forms.Padding(0,0,0,3)) }
`$StatusBar.Controls.Add(`$CountdownValueLabel,2,0)

# Pulse animation
function New-PulseFrameBitmap(`$Size,`$Scale,`$Alpha,`$BaseColor=`$null) {
    if (-not `$BaseColor) { `$BaseColor = `$ColorBlue1 } # default: bleu
    `$bmp = New-Object Drawing.Bitmap `$Size,`$Size
    `$gfx = [Drawing.Graphics]::FromImage(`$bmp); `$gfx.SmoothingMode='AntiAlias'
    `$color = [Drawing.Color]::FromArgb([math]::Min([math]::Max([int]`$Alpha,0),255),`$BaseColor.R,`$BaseColor.G,`$BaseColor.B)
    `$radius = (`$Size/1.2)*`$Scale
    `$rect = New-Object Drawing.RectangleF(((`$Size/2)-`$radius-0.6),((`$Size/2)-`$radius-0.6),(2*`$radius),(2*`$radius))
    `$gfx.FillEllipse((New-Object Drawing.SolidBrush `$color),`$rect)
    `$gfx.Dispose()
    return `$bmp
}
`$PulseAnim = @{ Size=15; Phase=0.0; Interval=30; Speed=0.05 }
`$PulsePictureBox.Image = New-PulseFrameBitmap `$PulseAnim.Size 0.9 200
`$PulseTimer = New-Object Windows.Forms.Timer -Property @{ Interval=`$PulseAnim.Interval }
`$PulseTimer.add_Tick({
    `$PulseAnim.Phase += `$PulseAnim.Speed
    `$sine = [math]::Sin(`$PulseAnim.Phase)/2.0
    `$scale = 0.75 + `$sine
    `$alpha = 120 + (`$sine*150)
    `$baseColor = `$ColorBlue1
    if (`$MainForm -and `$MainForm.Tag -and `$MainForm.Tag.ContainsKey('Remaining')) {if (`$MainForm.Tag['Remaining'] -lt 60) { `$baseColor = `$ColorRed }}
    `$oldImg,`$PulsePictureBox.Image = `$PulsePictureBox.Image,(New-PulseFrameBitmap `$PulseAnim.Size `$scale `$alpha `$baseColor)
    if (`$oldImg) { `$oldImg.Dispose() }
})

`$CloseButton = New-Object NoFocusButton
`$CloseButton.Text=`$Locale.ActionButton; `$CloseButton.Font=`$FontTextBold; `$CloseButton.Width=285
`$CloseButton.Dock='Right'; `$CloseButton.Margin=New-Object System.Windows.Forms.Padding(0,0,5,0)
`$CloseButton.FlatStyle='Flat'
`$CloseButton.FlatAppearance.MouseOverBackColor=`$ColorBlue2
`$CloseButton.FlatAppearance.MouseDownBackColor=`$ColorBlack
`$CloseButton.FlatAppearance.BorderSize=0
`$CloseButton.BackColor=`$ColorBlue1
`$CloseButton.ForeColor=[System.Drawing.Color]::White
`$CloseButton.add_MouseUp({ `$MainForm.ActiveControl = `$null })
`$CloseButton.add_Click({ Write-CustomLog "User click on Close button" ; `$MainForm.Close() })
`$CloseButton.TabStop = `$false

# Compose main layout sections
`$MainContent.Controls.Add(`$HeaderLabel,0,0)
`$MainContent.Controls.Add(`$CardBorderPanel,0,1)
`$MainContent.Controls.Add(`$CloseButton,0,3)
`$MainForm.Controls.Add(`$RootLayout)

# ----- Per-process item builder -----
function New-ProcessRowPanel(`$Icon,[string]`$DisplayDescription,[string]`$ExecutableName) {
    `$row = New-Object System.Windows.Forms.TableLayoutPanel
    `$row.Width=if (`$SidebarLogoBase64) {410} else {459}; `$row.Height=`$cardHeight; `$row.Margin = New-Object System.Windows.Forms.Padding 0,0,0,0
    `$row.BackColor=[System.Drawing.Color]::White; `$row.ColumnCount=2; `$row.RowCount=1
    `$null = `$row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle ([System.Windows.Forms.SizeType]::Absolute,64))) # Process icon
    `$null = `$row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle ([System.Windows.Forms.SizeType]::Percent,100))) # Process infos
    `$null = `$row.RowStyles.Add((New-Object System.Windows.Forms.RowStyle ([System.Windows.Forms.SizeType]::Percent,100))) 

    `$iconBox = New-Object System.Windows.Forms.PictureBox
    `$iconBox.SizeMode='CenterImage'; `$iconBox.Image=`$Icon; `$iconBox.Dock='Fill'

    `$textStack = New-Object System.Windows.Forms.TableLayoutPanel
    `$textStack.Dock='Fill'; `$textStack.ColumnCount=1; `$textStack.RowCount=2
    `$null = `$textStack.RowStyles.Add((New-Object System.Windows.Forms.RowStyle ([System.Windows.Forms.SizeType]::Percent,50))) # Process description
    `$null = `$textStack.RowStyles.Add((New-Object System.Windows.Forms.RowStyle ([System.Windows.Forms.SizeType]::Percent,50))) # Process name

    `$titleLabel = New-Object System.Windows.Forms.Label
    `$titleLabel.Text = if ([string]::IsNullOrEmpty(`$DisplayDescription)) { `$ExecutableName } else { `$DisplayDescription }
    `$titleLabel.Dock='Fill'; `$titleLabel.TextAlign='MiddleLeft'; `$titleLabel.Font=`$FontTextBoldUI
    `$titleLabel.ForeColor=`$ColorTextMain; `$titleLabel.AutoSize=`$false; `$titleLabel.AutoEllipsis=`$true

    `$exeLabel = New-Object System.Windows.Forms.Label
    `$exeLabel.Text=`$ExecutableName; `$exeLabel.Dock='Fill'; `$exeLabel.TextAlign='MiddleLeft'
    `$exeLabel.Font=`$FontSmall; `$exeLabel.ForeColor=`$ColorBlue1

    `$null = `$textStack.Controls.Add(`$titleLabel,0,0)
    `$null = `$textStack.Controls.Add(`$exeLabel,0,1)
    `$null = `$row.Controls.Add(`$iconBox,0,0)
    `$null = `$row.Controls.Add(`$textStack,1,0)
    return `$row
}

Write-CustomLog "Building UI rows for `$(`$detectedProcesses.Count) processes..."

`$psMajor = `$PSVersionTable.PSVersion.Major
foreach (`$proc in `$detectedProcesses) {
    if (`$ProcessFlow.Controls.Count -lt 3) {
        `$MainForm.Height += `$cardHeight
        `$CardLayout.RowStyles[1].Height += `$cardHeight * `$DPI_Factor
        `$MainContent.RowStyles[1].Height += `$cardHeight * `$DPI_Factor
    }
    `$itemPanel = New-ProcessRowPanel -Icon `$proc.Icon -DisplayDescription `$proc.Description -ExecutableName `$proc.Name
    `$ProcessFlow.Controls.Add(`$itemPanel) | Out-Null
}

try {
    [byte[]]`$logoBytes = [Convert]::FromBase64String(`$SidebarLogoBase64)
    `$ms  = New-Object System.IO.MemoryStream(`$logoBytes, `$false)
    `$img = [System.Drawing.Image]::FromStream(`$ms, `$true, `$true)
    `$bmp = New-Object System.Drawing.Bitmap(`$img)
    `$img.Dispose(); `$ms.Dispose()
    `$bmp.RotateFlip([System.Drawing.RotateFlipType]::Rotate270FlipNone)
    `$logoBox = New-Object TransparentPictureBox
    `$logoBox.Dock='Fill'; `$logoBox.SizeMode='Zoom'; `$logoBox.BackColor=[System.Drawing.Color]::Transparent; `$logoBox.Image=`$bmp
    [void]`$SidebarPanel.Controls.Add(`$logoBox)
} catch {}

# ----- Initial placement (bottom-right of primary working area) -----
`$MainForm.ResumeLayout()
`$work = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
`$MainForm.Location = New-Object System.Drawing.Point([Math]::Max(0,`$work.Right-`$MainForm.Width),[Math]::Max(0,`$work.Bottom-`$MainForm.Height))

# ----- Countdown timer (UI update + close at zero) -----
`$MainForm.Tag = @{ Remaining=[Math]::Max(0,`$Timer); CountdownTimer=(New-Object System.Windows.Forms.Timer) }
`$MainForm.Tag.CountdownTimer.Interval = 1000
`$MainForm.Tag.CountdownTimer.add_Tick({
    `$MainForm.Tag['Remaining'] = `$MainForm.Tag['Remaining'] - 1
    `$CountdownValueLabel.Text = Format-TimeString -TotalSeconds `$MainForm.Tag['Remaining'] -Loc `$Locale
    if (`$MainForm.Tag['Remaining'] -lt 60) { `$CountdownValueLabel.ForeColor = `$ColorRed } else { `$CountdownValueLabel.ForeColor = `$ColorTextMain }
    if (`$MainForm.Tag['Remaining'] -le 0)  { `$MainForm.Tag.CountdownTimer.Stop(); Write-CustomLog "Timer expired, closing form." ; `$MainForm.Close() }
})

# ----- Drag anywhere on sidebar or header, like a title bar -----
function Enable-WindowDragOnControl(`$Control) {
    `$Control.add_MouseDown({
        if (`$_.Button -eq [Windows.Forms.MouseButtons]::Left) {
            [Win32Native]::ReleaseCapture() | Out-Null
            [Win32Native]::SendMessage(`$MainForm.Handle,0xA1,0x2,0) | Out-Null
        }
    })
    foreach (`$child in `$Control.Controls) { Enable-WindowDragOnControl `$child }
}
Enable-WindowDragOnControl `$SidebarPanel
Enable-WindowDragOnControl `$MainContent.GetControlFromPosition(0,0)

# ----- Clamp to primary screen when drag ends, or when moved across screens -----
`$MessageHook = New-Object Win32MsgHelper `$MainForm
`$MessageHook.add_DragFinished({
    `$primary = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    `$frmBounds = `$MainForm.Bounds  # ← no more `$b collision
    `$x = [Math]::Max(`$primary.Left,[Math]::Min(`$frmBounds.Left,`$primary.Right-`$frmBounds.Width))
    `$y = [Math]::Max(`$primary.Top,[Math]::Min(`$frmBounds.Top,`$primary.Bottom-`$frmBounds.Height))
    if (`$x -ne `$frmBounds.Left -or `$y -ne `$frmBounds.Top -or [System.Windows.Forms.Screen]::FromControl(`$MainForm) -ne [System.Windows.Forms.Screen]::PrimaryScreen) {
        `$MainForm.Location = New-Object Drawing.Point `$x,`$y
    }
})

`$MainForm.add_Shown({ 
    Set-HeaderLabelHeight `$HeaderLabel `$Locale.InstallingOf `$PopupTitle
    Set-ControlRoundRegion `$MainForm 20; Set-ControlRoundRegion `$CardBorderPanel 12; Set-ControlRoundRegion `$CardPanel 10; Set-ControlRoundRegion `$ProcessBorderPanel 9; Set-ControlRoundRegion `$ProcessScrollPanel 7
    `$MainForm.Tag.CountdownTimer.Start()
    & `$AdjustInfoWidth
    `$PulseTimer.Start()
    Write-CustomLog "Form Shown."
})

`$MainForm.add_FormClosed({
    try { if (`$PulseTimer) { `$PulseTimer.Stop() } } catch {}
    try { if (`$PulsePictureBox -and `$PulsePictureBox.Image) { `$PulsePictureBox.Image.Dispose() } } catch {}
    try {
        if (`$ProcessFlow -and `$ProcessFlow.Controls) {
            foreach (`$row in `$ProcessFlow.Controls) {
                try {
                    `$pb = `$null
                    if (`$row -and `$row.Controls -and `$row.Controls.Count -gt 0) { `$pb = `$row.Controls[0] }
                    if (`$pb -and `$pb.Image) { `$pb.Image.Dispose() }
                } catch {}
            }
        }
    } catch {}
    try { if (`$logoBox -and `$logoBox.Image) { `$logoBox.Image.Dispose() } } catch {}
})

# ----- Show modal loop -----
[void][System.Windows.Forms.Application]::Run(`$MainForm)
"@
    return $PopupScript
}


# ==================================================================
#                                 MAIN
# ==================================================================

$NoPopup=$false
if (-not $PopupTitle) { $PopupTitle="CloseProcessPopup"; $NoPopup=$true } else { $PopupTitle=Format-Name $PopupTitle }
$script:LogPath = Resolve-LogPath -Title $PopupTitle -CandidateLog $Log
$script:LogName = Format-Name ([IO.Path]::GetFileNameWithoutExtension($script:LogPath))
Write-CustomLog "========================================="
Write-CustomLog "Starting BACKEND"
Write-CustomLog "========================================="
$sessionContext = Get-SessionContext
$PopupExitCode = $null
$launchOk      = $false
if (-not $sessionContext.IsSystem -and -not $sessionContext.IsProcessInteractive) {
    Write-CustomLog "This process is Non-interactive and not SYSTEM, with an active user session -> Not supported."
    Stop-Script 13
}
# --- Determine interactive target session (RDP or Console) ---
$targetSessionId = $null
if ($sessionContext.HasActiveUserSession -and $null -ne $sessionContext.ActiveUserSessionId) {
    $targetSessionId = [int]$sessionContext.ActiveUserSessionId
} else {
    $consoleSessionId = [WtsApi32]::WTSGetActiveConsoleSessionId()
    if ($consoleSessionId -ge 0) { $targetSessionId = $consoleSessionId }
}
# No interactive session at all -> exit 22
if ($null -eq $targetSessionId -or $targetSessionId -lt 0) {
    Write-CustomLog "No interactive session found (RDP/Console). Exiting with 22."
    Stop-Script 22
}

Write-CustomLog ("Current user    : " + $sessionContext.Name)
Write-CustomLog ("Is System       : " + $sessionContext.IsSystem)
Write-CustomLog ("Is Administrator: " + $sessionContext.IsAdmin)
Write-CustomLog ("Active session  : " + $sessionContext.ActiveUserSessionId + " (" + $sessionContext.ActiveUserSessionStation + ")")
Write-CustomLog ("Active user     : " + $sessionContext.ActiveUserFullName)

$detectedProcesses = Get-RunningProcesses -SessionId $targetSessionId -pwsh $pwsh -Processes $Process -ProcessesPaths $ProcessPath -ProcessTitles $ProcessTitle -ProcessDLL $ProcessDLL

if (-not $NoPopup) {
    $PopupScript    = Merge-PopupScript -PopupTitle $PopupTitle -Log $script:LogPath -detectedProcesses $detectedProcesses -Timer $Timer
    $launchResult = $null
    if ($sessionContext.IsSystem -or $sessionContext.IsProcessInteractive) {
        try {
            if ($sessionContext.IsSystem) {
                $launchResult = Start-FromSystemAsCurrentUser -SessionId $targetSessionId -Pwsh $pwsh -Script $PopupScript -ShowWindow:$Test -TimeoutSeconds ($Timer+120)
            } else {
                $launchResult = Start-FromCurrentUserStdin -Script $PopupScript
            }
        } catch {
            Write-CustomLog ("EXCEPTION during Popup launch: " + $_.Exception.Message)
            Stop-Script 4
        }
        $launchOk         = [bool]($launchResult -and $launchResult.Success)
        $PopupExitCode = if ($launchResult -and $launchResult.ContainsKey('ExitCode')) { [int]$launchResult.ExitCode } else { $null }
        Write-CustomLog ("Popup returned: Success=$launchOk, ExitCode=$PopupExitCode")
        if ($launchOk) {
            if ($PopupExitCode -eq 0) {
                Write-CustomLog "Popup Completed"
            } else {
                Write-CustomLog ("ERROR launching Popup: $PopupExitCode")
                if ($launchResult.ContainsKey('Error') -and $launchResult.Error) {
                    Write-CustomLog ("Error details: " + $launchResult.Error.Trim())
                }
                Stop-Script $PopupExitCode
            }
        } else {
            $ExitCode = if ($PopupExitCode) { $PopupExitCode } else { 12 }
            Write-CustomLog "ERROR: Popup not launched (ExitCode=$ExitCode)"
            if ($launchResult -and $launchResult.ContainsKey('Error') -and $launchResult.Error) {
                Write-CustomLog ("Error details: " + $launchResult.Error.Trim())
            }
            Stop-Script $ExitCode
        }
    } else {
        Write-CustomLog "ERROR: Unknown context."
        Stop-Script 14
    }
}


# ==================================================================
#                           CLOSE PROCESSES
# ==================================================================

function Close-detectedProcesses($detectedProcesses, [int]$Attempts = 8) {
    if (-not $detectedProcesses) { Write-CustomLog "Skip close: no detected items"; return }
    if ($Attempts -lt 1) { $Attempts = 1 }

    # Split targets: name-based vs PID-based (Title source => PID-only kill)
    $NameTargets=@()
    $PidTargets=@()
    $NamesFromTitle=@{} # names to exclude from /IM to avoid overkilling when Title was used

    foreach($d in $detectedProcesses){
        if($d -and $d.Process_Ids){
            if($d.CloseByPid){
                foreach($p in $d.Process_Ids){ if($p -is [int]){ $PidTargets+=,$p } }
                if($d.Name){ $NamesFromTitle[$d.Name.ToLowerInvariant()]=$true }
            }else{
                if($d.Name){ $NameTargets+=,$d.Name.Trim() }
            }
        }
    }
    $NameTargets = $NameTargets | Sort-Object | Select-Object -Unique
    $PidTargets  = $PidTargets  | Sort-Object | Select-Object -Unique
    if($NamesFromTitle.Count -gt 0){ $NameTargets = $NameTargets | Where-Object { -not $NamesFromTitle.ContainsKey($_.ToLowerInvariant()) } }

    function Invoke-Taskkill([string[]]$ProcessNames,[int]$Attempt){
        if (-not $ProcessNames -or $ProcessNames.Count -eq 0) { return }
        $batchSize = 30
        for($startIndex=0; $startIndex -lt $ProcessNames.Count; $startIndex += $batchSize){
            $processBatch = $ProcessNames[$startIndex..([Math]::Min($startIndex+$batchSize-1,$ProcessNames.Count-1))]
            $taskkillArgs = @('/F','/T')
            foreach($processName in $processBatch){ $taskkillArgs += @('/IM',$processName) }
            try {
                $taskkillOutput = & taskkill.exe @taskkillArgs 2>$null
                if ($taskkillOutput -and $taskkillOutput.Count -gt 0) {
                    Write-CustomLog ("Taskkill by name (attempt {0}):" -f $Attempt)
                    Write-CustomLog ($taskkillOutput -join [Environment]::NewLine)
                }
            } catch { Write-CustomLog ("ERROR: taskkill(/IM) failed (attempt {0}): {1}" -f $Attempt,$_.Exception.Message) }
        }
    }
    function Invoke-TaskkillByPid([int[]]$Pids,[int]$Attempt){
        if (-not $Pids -or $Pids.Count -eq 0) { return }
        $batchSize = 50
        for($startIndex=0; $startIndex -lt $Pids.Count; $startIndex += $batchSize){
            $pidBatch = $Pids[$startIndex..([Math]::Min($startIndex+$batchSize-1,$Pids.Count-1))]
            $taskkillArgs = @('/F')  # PID-only; do not use /T
            foreach($p in $pidBatch){ $taskkillArgs += @('/PID',([string]$p)) }
            try{
                $taskkillOutput = & taskkill.exe @taskkillArgs 2>$null
                if($taskkillOutput -and $taskkillOutput.Count -gt 0){
                    Write-CustomLog ("Taskkill by PID (attempt {0}):" -f $Attempt)
                    Write-CustomLog ($taskkillOutput -join [Environment]::NewLine)
                }
            }catch{ Write-CustomLog ("ERROR: taskkill(/PID) failed (attempt {0}): {1}" -f $Attempt,$_.Exception.Message) }
        }
    }
    function Get-AliveByName([string[]]$ProcessNames){
        $alive=@{}; if (-not $ProcessNames -or $ProcessNames.Count -eq 0) { return $alive }
        $batchSize=30
        for($startIndex=0;$startIndex -lt $ProcessNames.Count;$startIndex+=$batchSize){
            $processBatch=$ProcessNames[$startIndex..([Math]::Min($startIndex+$batchSize-1,$ProcessNames.Count-1))]
            $filterConditions=@(); foreach($processName in $processBatch){ $filterConditions+=("Name='{0}'" -f ($processName.Replace("'", "''"))) }
            $wmiFilter=$filterConditions -join " OR "
            try {
                $processRows=@(Get-WmiObject -Class Win32_Process -Filter $wmiFilter -ErrorAction SilentlyContinue)
                foreach($processRow in $processRows){ $alive[$processRow.Name.ToLowerInvariant()]=$true }
            } catch {}
        }
        return $alive
    }
    function Get-AliveByPid([int[]]$Pids){
        $alive=@{}; if(-not $Pids -or $Pids.Count -eq 0){ return $alive }
        $idList=($Pids | Sort-Object -Unique)
        $chunksize=50
        for($i=0;$i -lt $idList.Count;$i+=$chunksize){
            $chunk=$idList[$i..([Math]::Min($i+$chunksize-1,$idList.Count-1))]
            $filter=@(); foreach($p in $chunk){ $filter+=("ProcessId={0}" -f [string]$p) }
            $wmiFilter=($filter -join " OR ")
            try{ $rows=@(Get-WmiObject -Class Win32_Process -Filter $wmiFilter -ErrorAction SilentlyContinue); foreach($r in $rows){ $alive[[int]$r.ProcessId]=$true } }catch{}
        }
        return $alive
    }

    if($NameTargets.Count -gt 0){ Write-CustomLog ("Closing by name " + $NameTargets.Count + " process names via " + $Attempts + " grouped passes") }
    if($PidTargets.Count  -gt 0){ Write-CustomLog ("Closing by PID "  + $PidTargets.Count  + " PIDs via "          + $Attempts + " grouped passes") }

    for($attempt=1; $attempt -le $Attempts; $attempt++){
        if($NameTargets.Count -gt 0){ Write-CustomLog ("Taskkill(/IM) attempt " + $attempt + "/" + $Attempts); Invoke-Taskkill -ProcessNames $NameTargets -Attempt $attempt }
        if($PidTargets.Count  -gt 0){ Write-CustomLog ("Taskkill(/PID) attempt " + $attempt + "/" + $Attempts); Invoke-TaskkillByPid -Pids $PidTargets -Attempt $attempt }
        if($attempt -lt $Attempts){ Start-Sleep -Seconds 1 }
    }

    $survivorNames=@(); $survivorPids=@()
    if($NameTargets.Count -gt 0){ $aliveNames=Get-AliveByName -ProcessNames $NameTargets; foreach($n in $NameTargets){ if($aliveNames[$n.ToLowerInvariant()]){ $survivorNames+=,$n } } }
    if($PidTargets.Count  -gt 0){ $alivePids =Get-AliveByPid  -Pids $PidTargets;  foreach($p in $PidTargets){  if($alivePids[[int]$p]){ $survivorPids+=,$p } } }

    if(($survivorNames.Count -gt 0) -or ($survivorPids.Count -gt 0)){
        if($survivorNames.Count -gt 0){ Write-CustomLog ("ERROR: still running by name after " + $Attempts + " attempts: " + ($survivorNames -join ", ")) }
        if($survivorPids.Count  -gt 0){ Write-CustomLog ("ERROR: still running PIDs after "  + $Attempts + " attempts: " + (($survivorPids | ForEach-Object { [string]$_ }) -join ", ")) }
        Stop-Script 15
    }else{
        Write-CustomLog ("All targeted processes are no longer running after " + $Attempts + " attempts")
    }
}

if (-not $Test) {
    Write-CustomLog "Closing detected processes..."
    Close-detectedProcesses -detectedProcesses $detectedProcesses -Attempts $Attempts
} else { Write-CustomLog "Test mode -> not closing processes." }

Stop-Script 0
