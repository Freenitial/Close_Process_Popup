
<# ::
    @echo off & setlocal
    set "CPPversion=1.0"
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
    echo          List of process names to terminate.
    echo          Example: -Process "chrome=Google Chrome","acrobat.exe=Adobe Acrobat"
    echo.
    echo       -ProcessPath (string list)
    echo          Exe files inside specified directory (recursively) to terminate 
    echo          Example: -ProcessPath "C:\Program Files\Google\","C:\Program Files\Adobe"
    echo          End a path with '\' means exact folder (else startswith wildcard)
    echo.
    echo       -ProcessDLL (string list)
    echo          Scan processes that are using specified DLL
    echo          Example: -ProcessDLL acroRd32.dll,"C:\Program Files\Adobe\*.dll"
    echo          Supports dll filenames, or fullpath. Wildcard * also supported.
    echo.
    echo       -Product (string)
    echo          Mandatory. Display name of the product being installed.
    echo          Example: -Product "Adobe Acrobat"
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
    echo       cmd /c ""C:\Path\CloseProcessPopup.bat" -Product "ADOBE" -Processes "chrome.exe=Google Chrome","Acrord32=Acrobat Reader" -ProcessPath "C:\Program Files\Google","C:\Program Files\Adobe" -Log "C:\Logs""
    echo.
    echo       ^> SYSTEM 
    echo       schtasks /create /tn "SysPWSh" /tr "cmd /c \"\"C:\Path\backend.bat\" -Process \"chrome=chrome\" -Product \"ADOBE\" -test\"" /sc onstart /ru SYSTEM ^& schtasks /run /tn "SysPWSh" ^& schtasks /delete /tn "SysPWSh" /f
    echo.
    echo       ^> REMOTE 
    echo       powershell -Ex Bypass -Command "Invoke-Command -ComputerName %PC% -Authentication Negotiate -Credential (New-Object System.Management.Automation.PSCredential('%PC%\AdminName',(ConvertTo-SecureString 'AdminPassword' -AsPlainText -Force))) -ScriptBlock { param($batContent,$extraArgs) $Dest=\"$($env:SystemRoot)\Temp\CloseProcessPopup.bat\"; $utf8Bom = New-Object System.Text.UTF8Encoding $false; [System.IO.File]::WriteAllText($Dest,$batContent,$utf8Bom); ^& cmd.exe /c \"\"$Dest\" $extraArgs\"; $LASTEXITCODE } -ArgumentList (Get-Content -Path 'C:\SourcePath\CloseProcessPopup.bat' -Raw), '-Process \"Taskmgr.exe=Task Manager\" -Description \"Autodesk\" -test'"
    echo.    
    echo       ^> DOMAIN 
    echo       powershell -Ex Bypass -Command "Invoke-Command -ComputerName %PC% -ScriptBlock { param($batContent,$extraArgs) $Dest=\"$($env:SystemRoot)\Temp\CloseProcessPopup.bat\"; $utf8Bom = New-Object System.Text.UTF8Encoding $false; [System.IO.File]::WriteAllText($Dest,$batContent,$utf8Bom); ^& cmd.exe /c \"\"$Dest\" $extraArgs\"; $LASTEXITCODE } -ArgumentList (Get-Content -Path 'C:\SourcePath\CloseProcessPopup.bat' -Raw), '-Process \"Taskmgr.exe=Task Manager\" -Description \"Autodesk\" -test'"
    echo.
    echo.
    echo.
    echo    EXIT CODES:
    echo       ------
    echo    0   = Success (FrontEnd executed)
    echo    1   = Unknown general launch/error
    echo    2   = No requested processes are currently running
    echo    21  = Failed to enumerate processes
    echo    22  = No interactive session open
    echo    3   = Timeout waiting frontend process
    echo    4   = Exception during frontend launch
    echo    5   = Failed to create pipe / write to STDIN
    echo    6   = WTSEnumerateSessions failed
    echo    7   = WTSQueryUserToken failed
    echo    8   = DuplicateTokenEx failed
    echo    9   = CreateProcessAsUser failed
    echo    10  = No Admin nor System privilege at launch
    echo    11  = Missing arguments
    echo    12  = FrontEnd ExitCode unavailable
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
    [Parameter(Mandatory=$false)][Alias('Processes','CloseProcesses')]   [string[]]$Process,     # -Process     "chrome=Google Chrome","acrobat.exe=Adobe Acrobat"
    [Parameter(Mandatory=$false)][Alias('Path','Paths')]                 [string[]]$ProcessPath, # -ProcessPath "C:\Program Files\Google","C:\Program Files\Adobe"
    [Parameter(Mandatory=$false)][Alias('DLL','DLLpattern','UnlockDLL')] [string[]]$ProcessDLL,  # -ProcessDLL  acroRd32.dll,"C:\Program Files\Adobe\*.dll"
    [Parameter(Mandatory=$false)][Alias('Name','Description')]           [string]$Product,       # -Product     "Adobe Acrobat"
    [Parameter(Mandatory=$false)][Alias('CountDown')]                    [int]$Timer=600,        # -Timer 600   (in seconds)
    [Parameter(Mandatory=$false)][Alias('Retry')]                        [int]$Attempts=8,       # -Attempts 8  (kill process every second, 8 times)
    [Parameter(Mandatory=$false)][Alias('NoKill','ShowConsole')]         [switch]$Test,          # -Test        (do not kill processes after FrontEnd)
    [Parameter(Mandatory=$false)][Alias('LogFile','LogName','LogPath')]  [string]$Log            # -Log MyLog.log  OR  -Log C:\MyPath\MyLog.log
)
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Need Admin or System rights at launch"
    exit 10
}
if (-not ($product -and ($process -or $ProcessPath))) {
    $warn = "ERROR: Incorrect arguments provided. Required arguments:`n" +
            "   -Product xxx`n" +
            "       AND`n" +
            "   -Process xxx   OR   -ProcessPath xxx   OR   -ProcessDLL xxx`n"
    Write-Host $warn
    Write-Host "Arguments provided:`nProduct= $Product`nProcess= $Process`nProcessPath= $ProcessPath`nLog= $Log"
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
public class AdvApi32 {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode, EntryPoint="CreateProcessAsUserW")]
    public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
}
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct STARTUPINFO { public int cb; public string lpReserved; public string lpDesktop; public string lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }
[StructLayout(LayoutKind.Sequential)]
public struct LUID { public uint LowPart; public int HighPart; }
[StructLayout(LayoutKind.Sequential)]
public struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
[StructLayout(LayoutKind.Sequential)]
public struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }
public class WtsApi32 {
    [DllImport("wtsapi32.dll", SetLastError=true)]
    public static extern bool WTSQueryUserToken(int sessionId, out IntPtr Token);
    [DllImport("kernel32.dll")]
    public static extern int WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, out IntPtr ppSessionInfo, out int pCount);
    [DllImport("wtsapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, int wtsInfoClass, out IntPtr ppBuffer, out int pBytesReturned);
    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr pMemory);
}
[StructLayout(LayoutKind.Sequential)]
public struct WTS_SESSION_INFO { public int SessionId; public IntPtr pWinStationName; public int State; }
public class Win32Api {
    [Flags] public enum ProcessAccessFlags : uint { PROCESS_QUERY_INFORMATION=0x0400, PROCESS_VM_READ=0x0010 }
    [Flags] public enum ListModulesOptions : uint { LIST_MODULES_ALL=0x03 }
    public const int HANDLE_FLAG_INHERIT=0x1;
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle; }
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetHandleInformation(IntPtr hObject, int dwMask, int dwFlags);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    [DllImport("kernel32.dll", SetLastError = true)] 
    public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);
    [DllImport("psapi.dll", SetLastError = true)] 
    public static extern bool EnumProcesses([MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] int[] processIds, int size, [MarshalAs(UnmanagedType.U4)] out int bytesReturned);
    [DllImport("psapi.dll", SetLastError = true)] 
    public static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded);
    [DllImport("psapi.dll", CharSet = CharSet.Auto, SetLastError = true)] 
    public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, uint nSize);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)] 
    public static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);
}
"@


# ==================================================================
#                           UTILITIES
# ==================================================================

function Stop-Script([int]$ExitCode) {
    try {Write-CustomLog "========================================="; Write-CustomLog "" -noprefix} catch {}
    exit $ExitCode
}

function Save-IconToBase64Png([System.Drawing.Icon]$Icon) {
    if (-not $Icon) { return $null }
    $bmp = $Icon.ToBitmap()
    $ms  = New-Object IO.MemoryStream
    try {
        $bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png)
        [Convert]::ToBase64String($ms.ToArray())
    } catch { $null } finally { $ms.Dispose(); $bmp.Dispose() }
}


# ==================================================================
#                   LOGGING + PATH NORMALIZATION
# ==================================================================

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
    # Normalizes product name for filenames.
    $string = $RawName.Trim()
    $invalid = [IO.Path]::GetInvalidFileNameChars() + [IO.Path]::GetInvalidPathChars()
    foreach($ch in $invalid){ $string = $string -replace [Regex]::Escape([string]$ch), "_" }
    if ([string]::IsNullOrEmpty($string)) { $string = "Product" }
    elseif ($string.Length -gt 200) { $string = $string.Substring(0,200) }
    return $string
}

function Resolve-LogPath([string]$Product,[string]$CandidateLog) {
    # Define the log file path. Creates the folder if missing.
    $defaultName = "${Product}_CloseProcessPopup.log"
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
#                        SESSION CONTEXT
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


# ==================================================================
#                              DISCOVERY
# ==================================================================

function Get-RunningProcesses {
    <#
    Purpose : Build the detectedProcesses list with a single EnumProcesses scan:
    - Normalize the explicit -Process list ("exe" or "exe=Description").
    - Turn -ProcessPath entries into rules:
      * trailing "\" => Exact folder (that folder and its subfolders only)
      * no trailing "\" => Prefix (starts-with wildcard on the folder name)
    - Enumerate all processes ONCE using Win32 API:
      - If the process Name is in the requested set -> record it (Source=Explicit).
      - Else if its ExecutablePath matches any -ProcessPath rule -> auto-add (Source=Path, with rule detail) and record it.
      - If -ProcessDLL is specified, processes containing matching DLLs are auto-added (Source=DLL).
    - Aggregate PIDs by executable name, capture the first ExecutablePath seen, attach one Base64 PNG icon per exe.
    - Exit 2 if nothing is running.

    Returns detectedProcesses (array of hashtables):
        @{ Name; ShortName; Description; ExePath; IconBase64; Process_Ids[] }
    #>
    param(
        [string[]]$Processes,
        [string[]]$ProcessesPaths,
        [string[]]$ProcessDLL
    )

    # 1) -------------- Normalize the -Process entries --------------
    $requestedByLowerName = @{} # lower(name) -> @{ Name; ShortName; Description; Source='Explicit'; SourceDetail=$null }
    $explicitNamesLower = @{} # remembers names that came explicitly from -Process
    $parsedProcessArgs = $Processes
    foreach ($rawArgument in $parsedProcessArgs) {
        $executableNameRaw = $rawArgument
        $descriptionText = ""
        if ($rawArgument -like "*=*") {
            $keyValuePair = $rawArgument -split "=", 2
            $executableNameRaw = $keyValuePair[0]
            $descriptionText = $keyValuePair[1]
        }
        $executableName = $executableNameRaw.Trim('"',' ','\','/')
        $executableName = [IO.Path]::GetFileName($executableName)
        if ($executableName -notmatch '\.exe$') {
            $executableName += '.exe'
        }
        $descriptionText = $descriptionText.Trim()
        $lowerKey = $executableName.ToLowerInvariant()
        if (-not $requestedByLowerName.ContainsKey($lowerKey)) {
            $requestedByLowerName[$lowerKey] = @{
                Name = $executableName
                ShortName = ($executableName -replace '\.exe$','')
                Description = $descriptionText
                Source = 'Explicit'
                SourceDetail= $null
            }
            $explicitNamesLower[$lowerKey] = $true
        }
    }

    # 2) -------------- Normalize the -ProcessPath entries into rules --------------
    # Each rule = @{ Kind='Exact'|'Prefix'; RawInput=<as provided>; Normalized=<full path, normalized> }
    $pathRules = @()
    $parsedPathArgs = $ProcessesPaths
    foreach ($pathArgument in $parsedPathArgs) {
        if ([string]::IsNullOrEmpty($pathArgument)) { continue }
        $rawTrimmed = $pathArgument.Trim()
        $hadTrailingSep = ($rawTrimmed -match '[\\/]\s*$')
        $fullPathCandidate = $rawTrimmed.Trim('"')
        try {
            $fullPathCandidate = [IO.Path]::GetFullPath($fullPathCandidate)
        } catch { }
        if ([string]::IsNullOrEmpty($fullPathCandidate)) { continue }
        $norm = ($fullPathCandidate -replace '/','\')
        if ($hadTrailingSep -and ($norm -notmatch '[\\]$')) {
            $norm += '\'
        } # ensure explicit trailing "\" for Exact
        $kind = $(if ($hadTrailingSep) { 'Exact' } else { 'Prefix' })
        $pathRules += ,@{ Kind=$kind; RawInput=$rawTrimmed.Trim('"'); Normalized=$norm }
    }
    if ($pathRules.Count -gt 0) {
        $normForLog = @()
        foreach ($r in $pathRules) {
            $normForLog += ("{0}:{1}" -f $r.Kind, $r.Normalized)
        }
        Write-CustomLog ("ProcessPath rules: " + ($normForLog -join "; "))
    }

    function Test-PathMatchesRules([string]$candidatePath,[object[]]$rules) {
        # Returns the matching rule object or $null
        if ([string]::IsNullOrEmpty($candidatePath) -or -not $rules -or $rules.Count -eq 0) {
            return $null
        }
        foreach ($r in $rules) {
            if ($r.Kind -eq 'Exact') {
                # exact folder => requires normalized path with trailing "\" to avoid partial matches (e.g. "Google\" vs "Google Drive\")
                if ($candidatePath.StartsWith($r.Normalized, [System.StringComparison]::OrdinalIgnoreCase)) {
                    return $r
                }
            } else {
                # prefix => raw startswith (allows "Google" to match "Google Drive")
                if ($candidatePath.StartsWith($r.Normalized, [System.StringComparison]::OrdinalIgnoreCase)) {
                    return $r
                }
            }
        }
        return $null
    }

    # 3) -------------- Prepare DLL pattern --------------
    $dllPatternInfos = @()
    if ($ProcessDLL -and $ProcessDLL.Count -gt 0) {
        foreach ($pattern in $ProcessDLL) {
            if ($pattern) {
                $trimmed = $pattern.Trim()
                if ($trimmed) {
                    $dllPatternInfos += [pscustomobject]@{
                        PatternLower = $trimmed.ToLowerInvariant()
                        UseFileNameOnly = (-not ($trimmed -match '[\\/]'))
                    }
                }
            }
        }
        if ($dllPatternInfos.Count -gt 0) {
            $patternsForLog = ($ProcessDLL | Where-Object { $_ } | ForEach-Object { $_.Trim() }) -join ", "
            Write-CustomLog ("DLL patterns: " + $patternsForLog)
        }
    }

    # 4) -------------- Enumerate all processes ONCE --------------
    $modulePathSB = New-Object System.Text.StringBuilder 1024
    $procPathSB = New-Object System.Text.StringBuilder 1024
    $pointerSize = [IntPtr]::Size
    $moduleHandles = New-Object IntPtr[] 256
    $processIds = New-Object int[] 2048
    $bytesReturned = 0
    $detectedByLowerName = @{}
    if (-not [Win32Api]::EnumProcesses($processIds, $processIds.Length * 4, [ref]$bytesReturned)) {
        Write-CustomLog "Failed to enumerate processes"
        Stop-Script 2
    }
    $processCount = [int]($bytesReturned / 4)
    for ($processIndex = 0; $processIndex -lt $processCount; $processIndex++) {
        $processId = $processIds[$processIndex]
        if ($processId -eq 0) { continue }
        $processHandle = [IntPtr]::Zero
        try {
            $accessRights = [Win32Api+ProcessAccessFlags]::PROCESS_QUERY_INFORMATION -bor [Win32Api+ProcessAccessFlags]::PROCESS_VM_READ
            $processHandle = [Win32Api]::OpenProcess($accessRights, $false, $processId)
            if ($processHandle -eq [IntPtr]::Zero) { continue }
            # Get process full path
            [void]$procPathSB.Remove(0, $procPathSB.Length)
            $len = $procPathSB.Capacity
            $processFullPath = $null
            if ([Environment]::OSVersion.Version.Major -ge 6 -and [Win32Api]::QueryFullProcessImageName($processHandle, 0, $procPathSB, [ref]$len)) {
                $processFullPath = $procPathSB.ToString()
            } else {
                try {
                    $wmi = Get-WmiObject -Class Win32_Process -Filter "ProcessId=$processId" -ErrorAction Stop
                    $processFullPath = if ($wmi.ExecutablePath) { $wmi.ExecutablePath } else { $wmi.Name }
                } catch { }
            }
            if ([string]::IsNullOrEmpty($processFullPath)) { continue }
            $processName = [System.IO.Path]::GetFileName($processFullPath)
            $lowerName = $processName.ToLowerInvariant()
            # Check if process is relevant
            $isRelevant = $false
            $source = 'Explicit'
            $sourceDet = $null
            if ($requestedByLowerName.ContainsKey($lowerName)) {
                # A) Explicit process name from -Process
                $isRelevant = $true
                $source = 'Explicit'
            } else {
                # B) Check ProcessPath rules against ExecutablePath
                $matchedRule = Test-PathMatchesRules -candidatePath $processFullPath -rules $pathRules
                if ($matchedRule) {
                    if (-not $requestedByLowerName.ContainsKey($lowerName)) {
                        $requestedByLowerName[$lowerName] = @{
                            Name = $processName
                            ShortName = ($processName -replace '\.exe$','')
                            Description = ($processName -replace '\.exe$','')
                            Source = 'Path'
                            SourceDetail= $matchedRule.RawInput
                        }
                    }
                    $isRelevant = $true
                    $source = 'Path'
                    $sourceDet = $matchedRule.RawInput
                }
            }
            # C) Check DLL patterns
            $matchedDlls = @()
            if ($dllPatternInfos.Count -gt 0) {
                $requiredBytes = 0
                $bufferBytes = $moduleHandles.Length * $pointerSize
                if ([Win32Api]::EnumProcessModules($processHandle, $moduleHandles, $bufferBytes, [ref]$requiredBytes)) {
                    # Resize array if needed
                    if ($requiredBytes -gt $bufferBytes) {
                        $moduleHandles = New-Object IntPtr[] ([int][math]::Ceiling($requiredBytes / [double]$pointerSize))
                        $bufferBytes = $moduleHandles.Length * $pointerSize
                        if (-not [Win32Api]::EnumProcessModules($processHandle, $moduleHandles, $bufferBytes, [ref]$requiredBytes)) {
                            $requiredBytes = 0
                        }
                    }
                    if ($requiredBytes -gt 0) {
                        $moduleCount = [int]($requiredBytes / $pointerSize)
                        for ($moduleIndex = 0; $moduleIndex -lt $moduleCount; $moduleIndex++) {
                            $moduleHandle = $moduleHandles[$moduleIndex]
                            [void]$modulePathSB.Remove(0, $modulePathSB.Length)
                            [void][Win32Api]::GetModuleFileNameEx($processHandle, $moduleHandle, $modulePathSB, [uint32]$modulePathSB.Capacity)
                            $modulePath = $modulePathSB.ToString()
                            if ([string]::IsNullOrEmpty($modulePath)) { continue }
                            $modulePathLower = $modulePath.ToLowerInvariant()
                            $moduleFileLower = [System.IO.Path]::GetFileName($modulePathLower)
                            # Check against DLL patterns
                            foreach ($info in $dllPatternInfos) {
                                if ($info.UseFileNameOnly) {
                                    if ($moduleFileLower -like $info.PatternLower) {
                                        $matchedDlls += $moduleFileLower
                                        break
                                    }
                                } else {
                                    if ($modulePathLower -like $info.PatternLower) {
                                        $matchedDlls += $modulePath
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
                # If DLLs matched, mark process as relevant
                if ($matchedDlls.Count -gt 0) {
                    if (-not $isRelevant) {
                        if (-not $requestedByLowerName.ContainsKey($lowerName)) {
                            $requestedByLowerName[$lowerName] = @{
                                Name = $processName
                                ShortName = ($processName -replace '\.exe$','')
                                Description = ($processName -replace '\.exe$','')
                                Source = 'DLL'
                                SourceDetail= ($matchedDlls | Select-Object -First 3) -join ", "
                            }
                        }
                        $isRelevant = $true
                        $source = 'DLL'
                        $sourceDet = ($matchedDlls | Select-Object -First 3) -join ", "
                    }
                }
            }
            # Aggregate detected processes
            if ($isRelevant) {
                if (-not $detectedByLowerName.ContainsKey($lowerName)) {
                    $meta = $requestedByLowerName[$lowerName]
                    if (-not $meta) {
                        $meta = @{
                            Name=$processName;
                            ShortName=($processName -replace '\.exe$','');
                            Description=$processName;
                            Source=$source;
                            SourceDetail=$sourceDet
                        }
                        $requestedByLowerName[$lowerName] = $meta
                    }
                    $detectedByLowerName[$lowerName] = @{
                        Name = $meta.Name
                        ShortName = $meta.ShortName
                        Description = $meta.Description
                        ExePath = $processFullPath
                        IconBase64 = $null
                        Process_Ids = @()
                    }
                }
                $acc = $detectedByLowerName[$lowerName]
                $acc.Process_Ids += $processId
                if (-not $acc.ExePath) {
                    $acc.ExePath = $processFullPath
                }
            }
        } finally {
            if ($processHandle -ne [IntPtr]::Zero) {
                [void][Win32Api]::CloseHandle($processHandle)
            }
        }
    }

    # 5) -------------- Attach icons (cache results) --------------
    if ($detectedByLowerName.Count -ge 1) {
        Add-Type -AssemblyName System.Drawing
        $iconCacheByExePathLower = @{}
        foreach ($lowerKey in $detectedByLowerName.Keys) {
            $acc = $detectedByLowerName[$lowerKey]
            if ($acc.IconBase64) { continue }
            $iconBase64 = $null
            $firstPath = $acc.ExePath
            if ($firstPath -and (Test-Path -LiteralPath $firstPath)) {
                $exePathLower = $firstPath.ToLowerInvariant()
                if ($iconCacheByExePathLower.ContainsKey($exePathLower)) {
                    $iconBase64 = $iconCacheByExePathLower[$exePathLower]
                } else {
                    try {
                        $iconObject = [System.Drawing.Icon]::ExtractAssociatedIcon($firstPath)
                        if ($iconObject) {
                            $iconBase64 = Save-IconToBase64Png $iconObject
                        }
                    } catch { }
                    if (-not $iconBase64) {
                        $iconBase64 = Save-IconToBase64Png ([System.Drawing.SystemIcons]::Application)
                    }
                    $iconCacheByExePathLower[$exePathLower] = $iconBase64
                }
            } else {
                $iconBase64 = Save-IconToBase64Png ([System.Drawing.SystemIcons]::Application)
            }
            $acc.IconBase64 = $iconBase64
        }
    }

    # 6) -------------- Logging --------------
    $detectedProcesses = @()
    foreach ($lowerKey in $detectedByLowerName.Keys) {
        $detectedProcesses += ,$detectedByLowerName[$lowerKey]
    }
    $runningForLog = @()
    foreach ($lowerKey in $detectedByLowerName.Keys) {
        $entry = $detectedByLowerName[$lowerKey]
        $meta = $requestedByLowerName[$lowerKey]
        $src = if ($meta -and $meta.Source) { $meta.Source.ToUpper() } else { 'EXPLICIT' }
        $pidsDisplay = ($entry.Process_Ids) -join ","
        if ($meta -and $meta.Source -eq 'Path') {
            $runningForLog += (" -> [{0}] {1}`n     Match: {2}`n     PIDs: {3}" -f $src, $entry.Name, $entry.ExePath, $pidsDisplay)
        } elseif ($meta -and $meta.Source -eq 'DLL') {
            $runningForLog += (" -> [{0}] {1}`n     DLL: {2}`n     Process: {3}`n     PIDs: {4}" -f $src, $entry.Name, $meta.SourceDetail, $entry.ExePath, $pidsDisplay)
        } else {
            $runningForLog += (" -> [{0}] {1}`n     Source: {2}`n     PIDs: {3}" -f $src, $entry.Name, $entry.ExePath, $pidsDisplay)
        }
    }
    $missingExplicitNames = @()
    foreach ($lowerKey in $requestedByLowerName.Keys) {
        if ($explicitNamesLower.ContainsKey($lowerKey) -and (-not $detectedByLowerName.ContainsKey($lowerKey))) {
            $missingExplicitNames += $requestedByLowerName[$lowerKey].Name
        }
    }
    Write-CustomLog ("Items built: count=" + $detectedProcesses.Count)
    if ($runningForLog.Count -gt 0) {
        Write-CustomLog (" Running found:") -NoPrefix
        foreach ($line in $runningForLog) {
            Write-CustomLog "$line`n------" -NoPrefix
        }
    }
    if ($missingExplicitNames.Count -gt 0) {
        $missingDisplay = ($missingExplicitNames | Sort-Object -Unique) -join ", "
        Write-CustomLog (" Not running: " + $missingDisplay) -NoPrefix
    }
    if ($detectedProcesses.Count -eq 0) {
        Write-CustomLog "No requested processes are currently running. Exiting with code 2."
        Stop-Script 2
    }

    return ,$detectedProcesses
}


# ==================================================================
#                           FrontEnd STARTERS
# ==================================================================

function Get-PSVersionEncodedCMD {
    param([string]$FrontendScript)
    $psMajor = $PSVersionTable.PSVersion.Major
    if ($psMajor -ge 5) {
        $commandLine  = '[Console]::InputEncoding=[Text.Encoding]::UTF8; $sb=[ScriptBlock]::Create([Console]::In.ReadToEnd()); & $sb'
        return @{
            ArgumentLine   = "-NoLogo -NoProfile -Sta -ExecutionPolicy Bypass -Command ""$commandLine"""
            ScriptToSend   = $FrontendScript   # keep accents
        }
    } else {
        # Old powershell -> avoid accents (ASCII-only script)
        $noAccents = $FrontendScript
        $accentMap = @(
            @('à','a'),@('â','a'),@('ä','a'),@('é','e'),@('è','e'),@('ê','e'),@('ë','e'),@('î','i'),@('ï','i'),@('ô','o'),@('ö','o'),@('ù','u'),@('û','u'),@('ü','u'),@('ç','c'),
            @('À','A'),@('Â','A'),@('Ä','A'),@('É','E'),@('È','E'),@('Ê','E'),@('Ë','E'),@('Î','I'),@('Ï','I'),@('Ô','O'),@('Ö','O'),@('Ù','U'),@('Û','U'),@('Ü','U'),@('Ç','C')
        )
        foreach ($pair in $accentMap) { $noAccents = $noAccents -replace [Regex]::Escape($pair[0]), $pair[1] }
        return @{
            ArgumentLine   = '-NoLogo -NoProfile -Sta -ExecutionPolicy Bypass -'
            ScriptToSend   = $noAccents
        }
    }
}

function Start-FromCurrentUserStdin {
    param(
        [Parameter(Mandatory=$true)]  [string]$Pwsh,
        [Parameter(Mandatory=$true)]  [string]$FrontendScript,
        [Parameter(Mandatory=$false)] [switch]$ShowWindow,
        [Parameter(Mandatory=$false)] [int]$TimeoutSeconds = 600
    )
    $PSVersionEncodingMethod = Get-PSVersionEncodedCMD -FrontendScript $FrontendScript
    $argumentLine = $PSVersionEncodingMethod.ArgumentLine
    $scriptToSend = $PSVersionEncodingMethod.ScriptToSend
    Write-CustomLog "Launching FrontEnd..."
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName               = $Pwsh
        $startInfo.Arguments              = $argumentLine
        $startInfo.UseShellExecute        = $false
        $startInfo.RedirectStandardInput  = $true
        $startInfo.RedirectStandardOutput = $false
        $startInfo.RedirectStandardError  = $false
        $startInfo.CreateNoWindow         = (-not $ShowWindow)
        $startInfo.WindowStyle            = if ($ShowWindow) { [System.Diagnostics.ProcessWindowStyle]::Normal } else { [System.Diagnostics.ProcessWindowStyle]::Hidden }
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            return @{ Success=$false; ExitCode=4; Process_Id=$null; Error="Failed to start process" }
        }
        # Send script via STDIN
        try {
            $utf8NoBom   = New-Object System.Text.UTF8Encoding($false)
            $stdinWriter = New-Object System.IO.StreamWriter($process.StandardInput.BaseStream, $utf8NoBom, 4096)
            $stdinWriter.NewLine   = "`n"
            $stdinWriter.AutoFlush = $true
            $stdinWriter.Write($scriptToSend)
            $stdinWriter.Flush()
            $stdinWriter.Dispose()
        } catch {
            return @{ Success=$false; ExitCode=5; Process_Id=$process.Id; Error="Failed to write to STDIN: $($_.Exception.Message)" }
        }
        # Wait exit or timeout
        $timeoutMs = [int]([Math]::Max(1,$TimeoutSeconds) * 1000)
        if (-not $process.WaitForExit($timeoutMs)) {
            try { $process.Kill() } catch {}
            return @{ Success=$false; ExitCode=3; Process_Id=$process.Id; Error="Timeout after ${TimeoutSeconds}s" }
        }
        $exitCode = $null
        try { $exitCode = $process.ExitCode } catch {}
        if ($null -eq $exitCode) {
            return @{ Success=$false; ExitCode=12; Process_Id=$process.Id; Error="ExitCode unavailable" }
        }
        return @{ Success = ($exitCode -eq 0); ExitCode = $exitCode; Process_Id = $process.Id; Error = $null }
    }
    catch {
        return @{ Success=$false; ExitCode=4; Process_Id=$null; Error=$_.Exception.Message }
    }
}

function Start-FromSystemAsCurrentUser {
    <#
      Launch a PowerShell process in the interactive user's session (SYSTEM caller),
      stream a script via STDIN and wait for exit or timeout.
      Steps:
        - Resolve user token from SessionId
        - Duplicate token as primary
        - Create anonymous pipe for STDIN (parent writes -> child reads)
        - Call CreateProcessAsUser with bInheritHandles=$true
        - Stream FrontendScript through STDIN
        - Wait for exit or timeout
        - Return result object with Success/ExitCode/Process_Id
    #>
    param(
        [Parameter(Mandatory=$true)]  [int]$SessionId,
        [Parameter(Mandatory=$true)]  [string]$Pwsh,
        [Parameter(Mandatory=$true)]  [string]$FrontendScript,
        [Parameter(Mandatory=$false)] [switch]$ShowWindow,
        [Parameter(Mandatory=$false)] [int]$TimeoutSeconds = 600,
        [Parameter(Mandatory=$false)] [string]$WorkingDir = $(Split-Path -Path $Pwsh -Parent)
    )
    function Enable-Privilege([string]$PrivilegeName) {
        $TOKEN_ADJUST_PRIVILEGES = 0x20
        $TOKEN_QUERY             = 0x8
        $SE_PRIVILEGE_ENABLED    = 0x2
        $currentProcessHandle    = [Win32Api]::GetCurrentProcess()
        $processTokenHandle      = [IntPtr]::Zero
        if (-not [AdvApi32]::OpenProcessToken($currentProcessHandle,$TOKEN_ADJUST_PRIVILEGES -bor $TOKEN_QUERY,[ref]$processTokenHandle)) { return $false }
        try {
            $privilegeLuid = New-Object LUID
            if (-not [AdvApi32]::LookupPrivilegeValue($null,$PrivilegeName,[ref]$privilegeLuid)) { return $false }
            $privilegeAttributes = New-Object LUID_AND_ATTRIBUTES
            $privilegeAttributes.Luid=$privilegeLuid
            $privilegeAttributes.Attributes=$SE_PRIVILEGE_ENABLED
            $tokenPrivileges = New-Object TOKEN_PRIVILEGES
            $tokenPrivileges.PrivilegeCount=1
            $tokenPrivileges.Privileges=$privilegeAttributes
            [AdvApi32]::AdjustTokenPrivileges($processTokenHandle,$false,[ref]$tokenPrivileges,0,[IntPtr]::Zero,[IntPtr]::Zero) | Out-Null
            return $true
        } finally {
            if ($processTokenHandle -ne [IntPtr]::Zero) { [Win32Api]::CloseHandle($processTokenHandle) | Out-Null }
        }
    }
    # -------- Result object --------
    $result = @{ Success=$false; ExitCode=$null; Process_Id=$null }
    # -------- Handles --------
    $userTokenHandle= $primaryTokenHandle= $effectiveUserToken= $stdinReadHandle= $stdinWriteHandle= $processHandle= [IntPtr]::Zero
    try {
        # Resolve user token from active session
        [void](Enable-Privilege "SeIncreaseQuotaPrivilege")
        [void](Enable-Privilege "SeAssignPrimaryTokenPrivilege")
        if (-not [WtsApi32]::WTSQueryUserToken($SessionId,[ref]$userTokenHandle)) { 
            return @{ Success=$false; ExitCode=7; Process_Id=$null; Error="WTSQueryUserToken failed (SessionId=$SessionId)" }
        }
        # Duplicate token as primary
        $TOKEN_ALL_ACCESS       = 0xF01FF
        $SECURITY_IMPERSONATION = 2
        $TOKEN_TYPE_PRIMARY     = 1
        if (-not [AdvApi32]::DuplicateTokenEx($userTokenHandle,$TOKEN_ALL_ACCESS,[IntPtr]::Zero,$SECURITY_IMPERSONATION,$TOKEN_TYPE_PRIMARY,[ref]$primaryTokenHandle)) {
            return @{ Success=$false; ExitCode=8; Process_Id=$null; Error="DuplicateTokenEx failed" }
        }
        $effectiveUserToken=$primaryTokenHandle
        # Create anonymous pipe for STDIN
        $securityAttributes = New-Object Win32Api+SECURITY_ATTRIBUTES
        $securityAttributes.nLength=[Runtime.InteropServices.Marshal]::SizeOf([type]([Win32Api+SECURITY_ATTRIBUTES]))
        $securityAttributes.bInheritHandle=$true
        if (-not [Win32Api]::CreatePipe([ref]$stdinReadHandle,[ref]$stdinWriteHandle,[ref]$securityAttributes,0)) {
            return @{ Success=$false; ExitCode=5; Process_Id=$null; Error="CreatePipe failed" }
        }
        [void][Win32Api]::SetHandleInformation($stdinWriteHandle,[Win32Api]::HANDLE_FLAG_INHERIT,0)
        # Build STARTUPINFO for CreateProcessAsUser
        $startupInfo=New-Object STARTUPINFO
        $startupInfo.cb=[Runtime.InteropServices.Marshal]::SizeOf([type]([STARTUPINFO]))
        $startupInfo.lpDesktop='winsta0\default'
        $startupInfo.dwFlags=0x100
        $startupInfo.hStdInput =$stdinReadHandle
        $startupInfo.hStdOutput=[IntPtr]::Zero
        $startupInfo.hStdError =[IntPtr]::Zero
        if ($ShowWindow){$startupInfo.dwFlags=$startupInfo.dwFlags -bor 0x1; $startupInfo.wShowWindow=1}
        # Command line according to PS version
        $PSVersionEncodingMethod = Get-PSVersionEncodedCMD -FrontendScript $FrontendScript
        $argumentLine = $PSVersionEncodingMethod.ArgumentLine
        $scriptToSend = $PSVersionEncodingMethod.ScriptToSend
        # Flags
        $CREATE_NO_WINDOW=0x08000000; $CREATE_NEW_CONSOLE=0x00000010; $CREATE_BREAKAWAY_FROM_JOB=0x01000000
        $creationFlags=$(if($ShowWindow){$CREATE_NEW_CONSOLE}else{$CREATE_NO_WINDOW})
        $creationFlags=$creationFlags -bor $CREATE_BREAKAWAY_FROM_JOB
        # Launch process
        $processInfo=New-Object PROCESS_INFORMATION
        if (-not [AdvApi32]::CreateProcessAsUser($effectiveUserToken,$Pwsh,$argumentLine,[IntPtr]::Zero,[IntPtr]::Zero,$true,$creationFlags,[IntPtr]::Zero,$WorkingDir,[ref]$startupInfo,[ref]$processInfo)) { 
            $err=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
            return @{ Success=$false; ExitCode=4; Process_Id=$null; Error="CreateProcessAsUser failed (error=$err)" }
        }
        if ($processInfo.hThread -ne [IntPtr]::Zero) { [Win32Api]::CloseHandle($processInfo.hThread) | Out-Null }
        $processHandle=$processInfo.hProcess
        $result.Process_Id=$processInfo.dwProcessId
        # Stream script
        try {
            $safeStdinWrite=New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($stdinWriteHandle,$true)
            $stdinStream=New-Object System.IO.FileStream($safeStdinWrite,[System.IO.FileAccess]::Write,4096,$false)
            $writer=New-Object System.IO.StreamWriter($stdinStream,(New-Object System.Text.UTF8Encoding($false)))
            $writer.NewLine="`n"; $writer.AutoFlush=$true
            $writer.Write($scriptToSend); $writer.Dispose()
        } catch {
            return @{ Success=$false; ExitCode=5; Process_Id=$processInfo.dwProcessId; Error="Failed to write to STDIN: $($_.Exception.Message)" }
        }
        # Wait for exit or timeout
        $WAIT_OBJECT_0=0; $WAIT_TIMEOUT=258
        $waitMs=[int]([Math]::Max(1,$TimeoutSeconds)*1000)
        $waitResult=[Win32Api]::WaitForSingleObject($processHandle,[uint32]$waitMs)
        if ($waitResult -eq $WAIT_OBJECT_0) {
            $exitCode=0
            if([Win32Api]::GetExitCodeProcess($processHandle,[ref]$exitCode)) {
                return @{ Success=($exitCode -eq 0); ExitCode=$exitCode; Process_Id=$processInfo.dwProcessId; Error=$null }
            } else {
                return @{ Success=$false; ExitCode=12; Process_Id=$processInfo.dwProcessId; Error="ExitCode unavailable" }
            }
        }
        elseif ($waitResult -eq $WAIT_TIMEOUT) {
            try { [Win32Api]::TerminateProcess($processHandle,3) | Out-Null } catch {}
            return @{ Success=$false; ExitCode=3; Process_Id=$processInfo.dwProcessId; Error="Timeout after ${TimeoutSeconds}s" }
        }
        else {
            try { [Win32Api]::TerminateProcess($processHandle,4) | Out-Null } catch {}
            return @{ Success=$false; ExitCode=4; Process_Id=$processInfo.dwProcessId; Error="WaitForSingleObject failed" }
        }
    }
    catch {
        return @{ Success=$false; ExitCode=4; Process_Id=$null; Error=$_.Exception.Message }
    }
    finally {
        foreach($handle in $userTokenHandle,$primaryTokenHandle,$stdinReadHandle,$stdinWriteHandle,$processHandle) {
            if ($handle -ne [IntPtr]::Zero) { [Win32Api]::CloseHandle($handle) | Out-Null }
        }
    }
}


# ==================================================================
#                           FrontEnd SCRIPT
# ==================================================================

function Merge-FrontendScript($Product, $Log, $detectedProcesses, $Timer) {

    function Format-PSLiteral([string]$s){
        if($null -eq $s){ return "" }
        # In a string between single quotes, only ' must be doubled.
        return ($s -replace "'","''")
    }

    $Log     = Format-PSLiteral $Log
    $Product = Format-PSLiteral $Product
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

    $FrontendScript = @"
`$Log = '$Log'
`$Product = '$Product'
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
    `$line = "`$ts - [FrontEnd] - `$Message"
    try {
        `$streamWriter = New-Object IO.StreamWriter(`$Log,`$true,[Text.Encoding]::UTF8)
        `$streamWriter.WriteLine(`$line)
    } catch {} finally { if (`$streamWriter){`$streamWriter.Close()} }
    Write-Host `$line
}
Write-CustomLog "=== FrontEnd starting ==="

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
function Set-HeaderLabelHeight([System.Windows.Forms.Label]`$label,[string]`$prefix,[string]`$product) {
    `$maxSize = `$label.ClientSize
    if (`$maxSize.Width -le 0) { `$maxSize = [System.Drawing.Size]::new(580,63) } # fallback
    `$stringFormat = New-Object System.Drawing.StringFormat
    `$stringFormat.FormatFlags = [System.Drawing.StringFormatFlags]::LineLimit
    `$stringFormat.Trimming    = [System.Drawing.StringTrimming]::EllipsisWord
    `$graphics = [System.Drawing.Graphics]::FromHwnd(`$label.Handle)
    try {
        `$fullText   = "`$prefix`$product"
        `$measured   = `$graphics.MeasureString(`$fullText,`$label.Font,`$maxSize.Width,`$stringFormat)
        `$lineHeight = `$label.Font.Height
        `$threshold  = [math]::Ceiling(`$lineHeight * 1.5)
        if (`$measured.Height -le `$threshold) {
            `$label.Text = `$fullText
            `$label.AutoEllipsis = `$false
        } else {
            `$twoLines = "`$prefix`r`n`$product"
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
    Set-HeaderLabelHeight `$HeaderLabel `$Locale.InstallingOf `$Product
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
    return $FrontendScript
}


# ==================================================================
#                                 MAIN
# ==================================================================

$Product        = Format-Name $Product
$script:LogPath = Resolve-LogPath -Product $Product -CandidateLog $Log
$script:LogName = Format-Name ([IO.Path]::GetFileNameWithoutExtension($script:LogPath))
Write-CustomLog "========================================="
Write-CustomLog "Starting BACKEND"
Write-CustomLog "========================================="
$sessionContext = Get-SessionContext
$FrontEndExitCode = $null
$launchOk         = $false

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

# --- Build frontend script ---
$detectedProcesses = Get-RunningProcesses -Processes $Process -ProcessesPaths $ProcessPath -ProcessDLL $ProcessDLL
$FrontendScript    = Merge-FrontendScript -Product $Product -Log $script:LogPath -detectedProcesses $detectedProcesses -Timer $Timer
$launchResult = $null

if ($sessionContext.IsSystem -or $sessionContext.IsProcessInteractive) {
    try {
        if ($sessionContext.IsSystem) {
            $launchResult = Start-FromSystemAsCurrentUser -SessionId $targetSessionId -Pwsh $pwsh -FrontendScript $FrontendScript -ShowWindow:$Test -TimeoutSeconds ($Timer+30)
        } else {
            $launchResult = Start-FromCurrentUserStdin -Pwsh $pwsh -FrontendScript $FrontendScript -ShowWindow:$Test -TimeoutSeconds ($Timer+30)
        }
    } catch {
        Write-CustomLog ("EXCEPTION during FrontEnd launch: " + $_.Exception.Message)
        Stop-Script 4
    }
    $launchOk         = [bool]($launchResult -and $launchResult.Success)
    $FrontEndExitCode = if ($launchResult -and $launchResult.ContainsKey('ExitCode')) { [int]$launchResult.ExitCode } else { $null }
    Write-CustomLog ("FrontEnd returned: Success=$launchOk, ExitCode=$FrontEndExitCode")
    if ($launchOk) {
        if ($FrontEndExitCode -eq 0) {
            Write-CustomLog "FrontEnd Completed"
        } else {
            Write-CustomLog ("ERROR launching FrontEnd: $FrontEndExitCode")
            if ($launchResult.ContainsKey('Error') -and $launchResult.Error) {
                Write-CustomLog ("Error details: " + $launchResult.Error.Trim())
            }
            Stop-Script $FrontEndExitCode
        }
    } else {
        $ExitCode = if ($FrontEndExitCode) { $FrontEndExitCode } else { 12 }
        Write-CustomLog "ERROR: FrontEnd not launched (ExitCode=$ExitCode)"
        if ($launchResult -and $launchResult.ContainsKey('Error') -and $launchResult.Error) {
            Write-CustomLog ("Error details: " + $launchResult.Error.Trim())
        }
        Stop-Script $ExitCode
    }
} else {
    Write-CustomLog "ERROR: Unknown context."
    Stop-Script 14
}


# ==================================================================
#                           CLOSE PROCESSES
# ==================================================================

function Close-detectedProcesses($detectedProcesses, [int]$Attempts = 8) {
    if (-not $detectedProcesses) { Write-CustomLog "Skip close: no detected items"; return }
    if ($Attempts -lt 1) { $Attempts = 1 }
    $ProcessNames=@(); foreach($d in $detectedProcesses){ if($d.Name){ $ProcessNames += $d.Name.Trim() } }
    $ProcessNames = $ProcessNames | Sort-Object | Select-Object -Unique
    if (-not $ProcessNames -or $ProcessNames.Count -eq 0) { Write-CustomLog "Skip: no process names to close"; return }
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
                    Write-CustomLog ("Taskkill (attempt {0}):" -f $Attempt)
                    Write-CustomLog ($taskkillOutput -join [Environment]::NewLine)
                }
            } catch { Write-CustomLog ("ERROR: taskkill failed (attempt {0}): {1}" -f $Attempt,$_.Exception.Message) }
        }
    }
    function Get-Alive([string[]]$ProcessNames){
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
    Write-CustomLog ("Closing " + $ProcessNames.Count + " process names via " + $Attempts + " grouped passes (taskkill /F /T /IM)")
    for($attempt=1; $attempt -le $Attempts; $attempt++) { 
        Write-CustomLog ("Taskkill attempt " + $attempt + "/" + $Attempts)
        Invoke-Taskkill -ProcessNames $ProcessNames -Attempts $attempt
        if($attempt -lt $Attempts){ Start-Sleep -Seconds 1 } 
    }
    $final = Get-Alive -ProcessNames $ProcessNames
    $survivors=@(); foreach($n in $ProcessNames){ if($final[$n.ToLowerInvariant()]){ $survivors+=$n } }
    if ($survivors.Count -gt 0) { Write-CustomLog ("ERROR: still running after " + $Attempts + " attempts: " + ($survivors -join ", ")); Stop-Script 15 }
    else { Write-CustomLog ("All targeted process names are no longer running after " + $Attempts + " attempts") }
}

if (-not $Test) {
    Write-CustomLog "Closing detected processes..."
    Close-detectedProcesses -detectedProcesses $detectedProcesses -Attempts $Attempts
} else { Write-CustomLog "Test mode -> not closing processes." }

Stop-Script 0
