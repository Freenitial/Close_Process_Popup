<# ::
    cls & @echo off
    set "CPPversion=0.9"
    title Close Processes Popup v%CPPversion% Launcher

    setlocal EnableDelayedExpansion
    set "arch=x32"
    if "%PROCESSOR_ARCHITECTURE%"=="AMD64" set "arch=x64"
    if defined PROCESSOR_ARCHITEW6432      set "arch=x64"
    if exist %SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe   set "powershell=%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe"
    if exist %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe (set "powershell=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe")

    if /i "%~1"=="/?"       goto :help
    if /i "%~1"=="-?"       goto :help
    if /i "%~1"=="--?"      goto :help
    if /i "%~1"=="/help"    goto :help
    if /i "%~1"=="-help"    goto :help
    if /i "%~1"=="--help"   goto :help

    set "args=%*"
    copy /y "%~f0" "%SystemRoot%\Temp\CloseProcessPopup.ps1"
    %powershell% -Nologo -NoProfile -Ex Bypass -File "%SystemRoot%\Temp\CloseProcessPopup.ps1" !args!
    del /f "%SystemRoot%\Temp\CloseProcessPopup.ps1" & exit /b %errorlevel%  :: Return powershell errorlevel

    :help
    mode con: cols=128 lines=60
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
    echo       -Process "exe=Description" [,"exe2=Description2",...]
    echo          List of process names to terminate.
    echo          Example: -Process "chrome=Google Chrome","acrobat.exe=Adobe Acrobat"
    echo.
    echo       -ProcessPath "DirPath1","DirPath2"
    echo          Exe files inside specified directory (recursively) to terminate 
    echo          Example: -ProcessPath "C:\Program Files\Google\","C:\Program Files\Adobe"
    echo          End a path with '\' means exact folder (else startswith wildcard)
    echo.
    echo       -Product "ProductName"
    echo          Mandatory. Display name of the product being installed.
    echo          Example: -Product "Adobe Acrobat"
    echo.
    echo       -Message "Custom warning message"
    echo          Optional. Text displayed in the FrontEnd popup.
    echo          Example: -Message "Please close Chrome and Adobe Acrobat"
    echo.
    echo       -Timer N
    echo          Countdown in seconds before forced termination.
    echo          Default: 600 (10 minutes)
    echo          Example: -Timer 300
    echo.
    echo       -Attempts N
    echo          Number of repeated termination attempts.
    echo          Default: 8
    echo          Example: -Attempts 5
    echo.
    echo       -Test
    echo          Runs in test mode: FrontEnd shown but processes are not killed.
    echo.
    echo       -Log "PathOrFile"
    echo          Path to a custom log file.
    echo          Example: -Log "C:\Logs\CloseProcessPopup.log"
    echo.
    echo       -WorkDir "DirPath"
    echo          Working directory for temporary files and JSON payload.
    echo          If no -Log specified, will be used for logs too.
    echo          Example: -WorkDir "D:\Temp\CloseProcessPopup"
    echo.
    echo.
    echo    USAGE:
    echo       ------
    echo       Normal : cmd /c ""C:\Path\CloseProcessPopup.bat" -Product "ADOBE" -Processes "chrome.exe=Google Chrome","Acrord32=Acrobat Reader" -ProcessPath "C:\Program Files\Google","C:\Program Files\Adobe" -Log "C:\Logs" -WorkDir "C:\Temp"""
    echo       ------
    echo       System : schtasks /create /tn "SysPWSh" /tr "cmd /c \"\"C:\Path\backend.bat\" -Process \"chrome=chrome\" -Product \"ADOBE\" -test\"" /sc onstart /ru SYSTEM & schtasks /run /tn "SysPWSh" & schtasks /delete /tn "SysPWSh" /f
    echo       ------
    echo       Remote : powershell -NoLogo -NoProfile -Ex Bypass -Command "Invoke-Command -ComputerName %PC% -Authentication Negotiate -Credential (New-Object System.Management.Automation.PSCredential('%PC%\AdminName',(ConvertTo-SecureString 'AdminPassword' -AsPlainText -Force))) -ScriptBlock { param($batContent,$extraArgs) $Dest=\"$($env:SystemRoot)\Temp\CloseProcessPopup.bat\"; $utf8Bom = New-Object System.Text.UTF8Encoding $true; [System.IO.File]::WriteAllText($Dest,$batContent,$utf8Bom); & cmd.exe /c \"\"$Dest\" $extraArgs\"; $LASTEXITCODE } -ArgumentList (Get-Content -Path 'C:\SourcePath\CloseProcessPopup.bat' -Raw), '-Process \"Taskmgr.exe=Task Manager\" -Description \"Autodesk\" -test'"
    echo       ------
    echo       Domain : powershell -NoLogo -NoProfile -Ex Bypass -Command "Invoke-Command -ComputerName %PC% -ScriptBlock { param($batContent,$extraArgs) $Dest=\"$($env:SystemRoot)\Temp\CloseProcessPopup.bat\"; $utf8Bom = New-Object System.Text.UTF8Encoding $true; [System.IO.File]::WriteAllText($Dest,$batContent,$utf8Bom); & cmd.exe /c \"\"$Dest\" $extraArgs\"; $LASTEXITCODE } -ArgumentList (Get-Content -Path 'C:\SourcePath\CloseProcessPopup.bat' -Raw), '-Process \"Taskmgr.exe=Task Manager\" -Description \"Autodesk\" -test'"
    echo.
    echo.
    echo    EXIT CODES:
    echo       ------
    echo    0   = Success (FrontEnd executed)
    echo    1   = Unknown general launch/error
    echo    2   = No requested processes are currently running
    echo    22  = No interactive session open
    echo    3   = Failed to write FrontEnd script
    echo    4   = Failed to write JSON file
    echo    5   = SYSTEM token duplication/launch failure (WTSQueryUserToken/DuplicateTokenEx)
    echo    6   = WTS/privilege error other than no session
    echo    7   = WTSEnumerateSessions failed
    echo    8   = Some processes still running after taskkill
    echo    9   = MyInvocation.MyCommand.Path is null or unreachable
    echo    10  = No Admin nor System privilege at launch
    echo    11  = Missing arguments
    echo    12  = FrontEnd script return an error
    echo    13  = System task failed, can be related to FrontEnd script
    echo.
    echo    =============================================================================
    echo.
    pause >nul & exit /b
#>

#requires -version 2.0
Param(
    [Parameter(Mandatory=$false)][Alias('Processes','CloseProcesses')] [string[]]$Process,      # -Process "chrome=Google Chrome","acrobat.exe=Adobe Acrobat"
    [Parameter(Mandatory=$false)][Alias('Path','Paths')]               [string[]]$ProcessPath,  # -ProcessPath "C:\Program Files\Google","C:\Program Files\Adobe"
    [Parameter(Mandatory=$false)][Alias('Name','Description')]         [string]$Product,        # -Product "Adobe Acrobat"
    [Parameter(Mandatory=$false)][Alias('Text','Warning')]             [string]$Message,        # -Message "Please close Chrome and Adobe Acrobat"
    [Parameter(Mandatory=$false)][Alias('CountDown')]                  [int]$Timer=600,         # -Timer 600 (in seconds)
    [Parameter(Mandatory=$false)][Alias('Retry')]                      [int]$Attempts=8,        # -Attempts 8 (kill process every second, 8 times)
    [Parameter(Mandatory=$false)]                                      [switch]$Test,           # -Test (do not kill processes after FrontEnd)
    [Parameter(Mandatory=$false)][Alias('LogFile','LogName','LogPath')][string]$Log,            # -Log MyLog.log  OR  -Log C:\MyPath\MyLog.log
    [Parameter(Mandatory=$false)]                                      [string]$WorkDir,        # -WorkDir "C:\CustomTemp"
    [Parameter(Mandatory=$false)][Alias('JSON')]                       [string]$JsonPath        # Internal use to self-relanch or launch FrontEnd
)
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "ERROR: Need Admin or System rights at launch"
    exit 10
}
if (-not (($product -and ($process -or $ProcessPath)) -or ($JsonPath -and $Log))) {
    $warn = "ERROR: Incorrect arguments provided. Please input one of these required args method:`n" +
            "  1st way : (-Product `"YourProduct`")   AND (-Process `"MyProcess=Description`" AND/OR -ProcessPath `"ProcessParentDir=Description`")`n" +
            "  2nd way : (-JsonPath `"YourJsonPath`") AND (-Log `"YourLogPath`")"
    Write-Error $warn
    exit 11
}

# ------------------------- Native P/Invoke -------------------------
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
public class AdvApi32 {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);
    [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
    public static extern bool LookupAccountSid(string lpSystemName, IntPtr Sid, StringBuilder lpName, ref uint cchName, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out int peUse);
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
public struct TOKEN_USER { public SID_AND_ATTRIBUTES User; }
[StructLayout(LayoutKind.Sequential)]
public struct SID_AND_ATTRIBUTES { public IntPtr Sid; public int Attributes; }
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
    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr pMemory);
}
[StructLayout(LayoutKind.Sequential)]
public struct WTS_SESSION_INFO { public int SessionId; public IntPtr pWinStationName; public int State; }
public class Kernel32 {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}
public class UserEnv {
    [DllImport("userenv.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
    [DllImport("userenv.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
}
"@

# ==================================================================
#                           UTILITIES
# ==================================================================

function Stop-Script([int]$ExitCode) {
    if (-not $Test.IsPresent) {
        if ($JsonPath     -and (Test-Path $JsonPath))    {try {Remove-Item -LiteralPath $JsonPath -Force}    catch{Write-CustomLog "WARN: Cannot remove JSON file '$JsonPath'"}}
        if ($FrontEndpath -and (Test-Path $FrontEndpath)){try {Remove-Item -LiteralPath $FrontEndpath -Force}catch{Write-CustomLog "WARN: Cannot remove FrontEnd script '$FrontEndpath'"}}
    }
    try {Write-CustomLog "========================================="; Write-CustomLog ""} catch {}
    exit $ExitCode
}

function Format-CommandLineArgument([string]$s) {
    if ($null -eq $s) { return '""' }
    '"' + ($s -replace '"','\"') + '"'
}

function Resolve-PwshExe {
    # Returns the correct Powershell.exe path (Sysnative for 32-bit host on 64-bit OS)
    $sys32    = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
    $sysNative= Join-Path $env:WINDIR "Sysnative\WindowsPowerShell\v1.0\powershell.exe"
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and (Test-Path $sysNative)) { return $sysNative }
    $sys32
}

function ConvertFrom-CsvLikeArray([string[]]$InputValues) {
    # Accept either an array or a single "CSV-like" string with quotes.
    if (-not $InputValues -or $InputValues.Count -eq 0) { return @() }
    # Case 1: one single string containing commas -> parse as CSV-like (handles quotes)
    if ($InputValues.Count -eq 1 -and ($InputValues[0] -match ',')) {
        $parsedValues = @()
        foreach ($regexMatch in [regex]::Matches($InputValues[0], '(?:"([^"]*)")|([^,]+)')) {
            $rawValue = if ($regexMatch.Groups[1].Success) {$regexMatch.Groups[1].Value} else {$regexMatch.Groups[2].Value}
            if ($rawValue) {
                $cleanValue = $rawValue.Trim()
                if ($cleanValue.Length -gt 0) { $parsedValues += $cleanValue }
            }
        }
        return $parsedValues
    }
    # Case 2: treat input as an array -> trim each entry and remove empty strings
    $normalizedValues = @()
    foreach ($inputItem in $InputValues) {
        if ($inputItem) {
            $cleanItem = $inputItem.Trim()
            if ($cleanItem.Length -gt 0) { $normalizedValues += $cleanItem }
        }
    }
    return $normalizedValues
}

function ConvertTo-JsonEscapedString([string]$s) {
    if ($null -eq $s) { return "" }
    $s = $s -replace '\\','\\\\'
    $s = $s -replace '"','\"'
    $s = $s -replace "`r",'\\r'
    $s = $s -replace "`n",'\\n'
    $s = $s -replace "`t",'\\t'
    $s
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

function Write-CustomLog { param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "$ts - $Message"
    try {
        $sw = New-Object IO.StreamWriter($script:LogPath, $true, [Text.Encoding]::UTF8)
        $sw.WriteLine($line)
    } catch {} finally { if ($sw) { $sw.Close() } }
    Write-Host $line
}

function Format-Name([string]$RawName) {
    # Normalizes product name for filenames.
    $s = $RawName.Trim()
    $invalid = [IO.Path]::GetInvalidFileNameChars() + [IO.Path]::GetInvalidPathChars()
    foreach($ch in $invalid){ $s = $s -replace [Regex]::Escape([string]$ch), "_" }
    if ([string]::IsNullOrEmpty($s)) { $s = "Product" }
    elseif ($s.Length -gt 200) { $s = $s.Substring(0,200) }
    return $s
}

function Resolve-WorkDir([string]$CandidateWorkDir) {
    # Chooses a usable temp working directory and creates it if needed.
    if ([string]::IsNullOrEmpty($CandidateWorkDir) -or $CandidateWorkDir.Trim().Length -eq 0) {
        $dir = Join-Path $env:WINDIR "Temp"
        Write-Host "TempDir not provided -> using default $dir"
    } else {
        $dir = $CandidateWorkDir.Trim('"',' ')
        foreach ($invalidChar in [IO.Path]::GetInvalidPathChars()) {
            if ($dir.Contains($invalidChar)) { $dir = $dir -replace [Regex]::Escape([string]$invalidChar),'_' }
        }
        try { [void][IO.Path]::GetFullPath($dir); Write-Host "TempDir validated -> $dir" }
        catch { $dir = Join-Path $env:WINDIR "Temp"; Write-Error "Invalid TempDir provided -> fallback to $dir" }
    }
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
        try { New-Item -Path $dir -Type Directory -Force | Out-Null; Write-Host "TempDir did not exist, created: $dir" }
        catch { $dir = Join-Path $env:WINDIR "Temp"; Write-Error "Failed to create TempDir, fallback to $dir" }
    }
    return $dir
}

function Resolve-LogPath([string]$WorkDir,[string]$Product,[string]$CandidateLog) {
    # Define the log file path. Creates the folder if missing.
    $safeProduct = ($Product -replace '[^\w\-]', '_')
    $defaultName = "${safeProduct}_CloseProcessPopup.log"
    if ([string]::IsNullOrEmpty($CandidateLog)) { $path = Join-Path $WorkDir $defaultName }
    elseif ($CandidateLog -match '[\\/]' -and (Test-Path $CandidateLog -PathType Container)) { $path = Join-Path $CandidateLog $defaultName }
    else {
        $leaf = if ($CandidateLog -match '[\\/]') { [IO.Path]::GetFileName($CandidateLog) } else { $CandidateLog }
        if ($leaf -notmatch 'popup') { $leaf = [IO.Path]::GetFileNameWithoutExtension($leaf) + "_CloseProcessPopup" + [IO.Path]::GetExtension($leaf) }
        if ([string]::IsNullOrEmpty([IO.Path]::GetExtension($leaf))) { $leaf += ".log" }
        $dir = if ($CandidateLog -match '[\\/]') { Split-Path $CandidateLog -Parent } else { $WorkDir }
        if (-not $dir) { $dir = $WorkDir }
        $path = Join-Path $dir $leaf
    }
    $parentDir = [IO.Path]::GetDirectoryName($path)
    if (-not (Test-Path -LiteralPath $parentDir -PathType Container)) {
        New-Item -Path $parentDir -Type Directory -Force | Out-Null
    }
    $script:LogPath = $path
    return $path
}

# ==================================================================
#                        SESSION CONTEXT
# ==================================================================

function Get-SessionContext {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $principalInfo = @{
        Name                      = $currentIdentity.Name
        IsSystem                  = $currentIdentity.IsSystem
        IsAdmin                   = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        IsProcessInteractive      = [Environment]::UserInteractive
        SessionName               = $env:SESSIONNAME
        CurrentProcessSessionId   = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        HasActiveUserSession      = $false
        ActiveUserSessionId       = $null
        ActiveUserSessionStation  = $null
        DetectionMethod           = "Unknown"
    }
    # WTSEnumerateSessions
    try {
        $sessionsPointer = [IntPtr]::Zero; $sessionCount = 0
        if ([WtsApi32]::WTSEnumerateSessions([IntPtr]::Zero,0,1,[ref]$sessionsPointer,[ref]$sessionCount)) {
            $structSize = [Runtime.InteropServices.Marshal]::SizeOf([type]([WTS_SESSION_INFO]))
            $cursorPtr  = $sessionsPointer
            for ($i=0; $i -lt $sessionCount; $i++) {
                $sessionInfo = [Runtime.InteropServices.Marshal]::PtrToStructure($cursorPtr,[type]([WTS_SESSION_INFO]))
                $stationName = [Runtime.InteropServices.Marshal]::PtrToStringUni($sessionInfo.pWinStationName)
                if (($sessionInfo.State -eq 0) -and $stationName -and ($stationName -ne 'Services')) {
                    $principalInfo.HasActiveUserSession      = $true
                    $principalInfo.ActiveUserSessionId       = $sessionInfo.SessionId
                    $principalInfo.ActiveUserSessionStation  = $stationName
                    $principalInfo.DetectionMethod           = "WTSEnumerateSessions"
                    break
                }
                $cursorPtr = [IntPtr]::Add($cursorPtr,$structSize)
            }
            [WtsApi32]::WTSFreeMemory($sessionsPointer)
        }
    } catch { 
        Write-CustomLog ("WTSEnumerateSessions exception: " + $_.Exception.Message)
        Stop-Script 7 
    }
    # Fallback: query.exe session
    Write-CustomLog ("IsProcessInteractive: " + $principalInfo.IsProcessInteractive + " (SessionName=" + ($principalInfo.SessionName -as [string]) + ", ProcSessionId=" + $principalInfo.CurrentProcessSessionId + ")")
    Write-CustomLog ("HasActiveUserSession: " + $principalInfo.HasActiveUserSession + " (ActiveSessionId=" + ($principalInfo.ActiveUserSessionId -as [string]) + ", Station=" + ($principalInfo.ActiveUserSessionStation -as [string]) + ", Method=" + $principalInfo.DetectionMethod + ")")
    return $principalInfo
}


# ==================================================================
#                              DISCOVERY
# ==================================================================

function Get-RunningProcesses {
    <#
    Purpose :
        Build the DetectedProcesses list with a single WMI pass:
        - Normalize the explicit -Process list ("exe" or "exe=Description").
        - Turn -ProcessPath entries into case-insensitive prefix checks.
        - Enumerate Win32_Process ONCE:
            - If the process Name is in the requested set -> record it.
            - Else if its ExecutablePath starts with any provided prefix -> auto-add the name (discovered) and record it.
        - Aggregate PIDs by executable name, capture the first ExecutablePath seen,
          and attach one Base64 PNG icon per detected executable.
        - Exit 2 if nothing is running.
    Input :
        -Processes      : string[] (array or single CSV-like string)
        -ProcessesPaths : string[] (array or single CSV-like string)
    Returns DetectedProcesses (array of hashtables):
        @{ Name; ShortName; Description; ExePath; IconBase64; Process_Ids[] }
    #>
    param([string[]]$Processes, [string[]]$ProcessesPaths)
    # 1) -------------- Normalize the -Process entries --------------
    $requestedByLowerName = @{}    # lower(name) -> @{ Name; ShortName; Description }
    $explicitNamesLower   = @{}    # set to remember which names came explicitly from -Process
    $parsedProcessArgs = ConvertFrom-CsvLikeArray $Processes
    foreach ($rawArgument in $parsedProcessArgs) {
        $executableNameRaw = $rawArgument
        $descriptionText   = ""
        # Accept "exe=Description"
        if ($rawArgument -like "*=*") {
            $keyValuePair     = $rawArgument -split "=", 2
            $executableNameRaw = $keyValuePair[0]
            $descriptionText   = $keyValuePair[1]
        }
        # Normalize to a clean file name (keep only leaf, strip quotes/slashes)
        $executableName = $executableNameRaw.Trim('"',' ','\','/')
        $executableName = [IO.Path]::GetFileName($executableName)
        if ($executableName -notmatch '\.exe$') { $executableName += '.exe' }
        $descriptionText = $descriptionText.Trim()
        $lowerKey = $executableName.ToLowerInvariant()
        if (-not $requestedByLowerName.ContainsKey($lowerKey)) {
            $requestedByLowerName[$lowerKey] = @{
                Name        = $executableName
                ShortName   = ($executableName -replace '\.exe$','')
                Description = $descriptionText
            }
            $explicitNamesLower[$lowerKey] = $true
        }
    }
    # 2) -------------- Normalize the -ProcessPath entries into prefixes --------------
    $pathPrefixes = @()
    $parsedPathArgs = ConvertFrom-CsvLikeArray $ProcessesPaths
    foreach ($pathArgument in $parsedPathArgs) {
        if ([string]::IsNullOrEmpty($pathArgument)) { continue }
        $fullPathCandidate = $pathArgument.Trim().Trim('"')
        try { $fullPathCandidate = [IO.Path]::GetFullPath($fullPathCandidate) } catch { }
        if ([string]::IsNullOrEmpty($fullPathCandidate)) { continue }
        $pathPrefixes += $fullPathCandidate
    }
    if ($pathPrefixes.Count -gt 0) {
        $pathPrefixes = $pathPrefixes | Sort-Object -Unique
        Write-CustomLog ("ProcessPath normalized: " + ($pathPrefixes -join "; "))
    }
    function Test-PathStartsWithAnyPrefix([string]$candidatePath,[string[]]$prefixes) {
        # Helper: prefix check with OrdinalIgnoreCase
        if ([string]::IsNullOrEmpty($candidatePath) -or -not $prefixes -or $prefixes.Count -eq 0) { return $false }
        foreach ($prefix in $prefixes) {
            if ($candidatePath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
        return $false
    }
    # 3) -------------- Enumerate Win32_Process once and aggregate results --------------
    $allProcesses = @()
    try { $allProcesses = @(Get-WmiObject Win32_Process -ErrorAction SilentlyContinue) } catch { }
    # detectedByLowerName: lower(name) -> accumulator
    # accumulator = @{ Name; ShortName; Description; ExePath(first); IconBase64(null for now); Process_Ids (int list) }
    $detectedByLowerName = @{}
    foreach ($wmiProcess in $allProcesses) {
        # Safely read the needed fields
        $processName   = $null; try  { $processName    = $wmiProcess.Name }           catch { }
        if (-not $processName)       { continue }
        $executablePath = $null; try { $executablePath = $wmiProcess.ExecutablePath } catch { }
        $processId      = $null; try { $processId      = [int]$wmiProcess.ProcessId } catch { }
        $lowerName = $processName.ToLowerInvariant()
        $isRelevant = $false
        if ($requestedByLowerName.ContainsKey($lowerName)) {
            #   A) Executable name provided with -Process
            $isRelevant = $true
        } elseif (Test-PathStartsWithAnyPrefix -candidatePath $executablePath -prefixes $pathPrefixes) {
            #   B) ExecutablePath starts with any provided -ProcessPath
            if (-not $requestedByLowerName.ContainsKey($lowerName)) {
                $requestedByLowerName[$lowerName] = @{
                    Name        = $processName
                    ShortName   = ($processName -replace '\.exe$','')
                    Description = ($processName -replace '\.exe$','')
                }
            }
            $isRelevant = $true
        }
        if (-not $isRelevant) { continue }
        # Ensure an accumulator exists for that name
        if (-not $detectedByLowerName.ContainsKey($lowerName)) {
            $meta = $requestedByLowerName[$lowerName]
            $detectedByLowerName[$lowerName] = @{
                Name        = $meta.Name
                ShortName   = $meta.ShortName
                Description = $meta.Description
                ExePath     = $null
                IconBase64  = $null
                Process_Ids = @()
            }
        }
        # Append PID and ExecutablePath
        $acc = $detectedByLowerName[$lowerName]
        if ($null -ne $processId) { $acc.Process_Ids += $processId }
        if (-not $acc.ExePath -and $executablePath) { $acc.ExePath = $executablePath }
    }
    # 4) -------------- Attach icons (cache results) --------------
    if ($detectedByLowerName.Count -ge 1) {
        Add-Type -AssemblyName System.Drawing
        $iconCacheByExePathLower = @{}
        foreach ($lowerKey in $detectedByLowerName.Keys) {
            $acc = $detectedByLowerName[$lowerKey]
            if ($acc.IconBase64) { continue } # already set (unlikely here)
            $iconBase64 = $null
            $firstPath  = $acc.ExePath
            if ($firstPath -and (Test-Path -LiteralPath $firstPath)) {
                $exePathLower = $firstPath.ToLowerInvariant()
                if ($iconCacheByExePathLower.ContainsKey($exePathLower)) {
                    $iconBase64 = $iconCacheByExePathLower[$exePathLower]
                } else {
                    try {
                        $iconObject = [System.Drawing.Icon]::ExtractAssociatedIcon($firstPath)
                        if ($iconObject) { $iconBase64 = Save-IconToBase64Png $iconObject }
                    } catch { }
                    if (-not $iconBase64) { $iconBase64 = Save-IconToBase64Png ([System.Drawing.SystemIcons]::Application) }
                    $iconCacheByExePathLower[$exePathLower] = $iconBase64
                }
            } else {
                # No executable path available -> use a generic icon
                $iconBase64 = Save-IconToBase64Png ([System.Drawing.SystemIcons]::Application)
            }
            $acc.IconBase64 = $iconBase64
        }
    }
    # 5) -------------- Logging --------------
    $detectedProcesses = @()
    $runningNamesForLog = @()
    foreach ($lowerKey in $detectedByLowerName.Keys) {
        $detectedProcesses += ,$detectedByLowerName[$lowerKey]
        $runningNamesForLog += $detectedByLowerName[$lowerKey].Name
    }
    $missingExplicitNames = @()
    foreach ($lowerKey in $requestedByLowerName.Keys) {
        if ($explicitNamesLower.ContainsKey($lowerKey) -and (-not $detectedByLowerName.ContainsKey($lowerKey))) {
            $missingExplicitNames += $requestedByLowerName[$lowerKey].Name
        }
    }
    Write-CustomLog ("Items built: count=" + $detectedProcesses.Count)
    if ($runningNamesForLog.Count -gt 0) {
        Write-CustomLog ("  Running found: ")
        foreach ($entry in $detectedProcesses) {
            Write-CustomLog ("    -> " + $entry.Name + " -> PIDs: " + (($entry.Process_Ids) -join ",")) 
        }
    }
    if ($missingExplicitNames.Count -gt 0) {
        $missingDisplay = ($missingExplicitNames | Sort-Object -Unique) -join ", "
        Write-CustomLog ("  Not running:  " + $missingDisplay)
    }
    if ($detectedProcesses.Count -eq 0) {
        Write-CustomLog "No requested processes are currently running. Exiting with code 2."
        Stop-Script 2
    }
    return ,$detectedProcesses
}


# ==================================================================
#                   JSON STATE (WRITE / READ SHORTCUT)
# ==================================================================

function Merge-JsonPayload([string]$Product,[string]$Message,[int]$Timer,[array]$DetectedProcesses,[string]$WorkDir,[string]$Log,[int]$Attempts,[bool]$Test){
    $StringBuilder = New-Object Text.StringBuilder
    [void]$StringBuilder.Append('{')
    [void]$StringBuilder.Append('"Product":"');      [void]$StringBuilder.Append((ConvertTo-JsonEscapedString $Product));      [void]$StringBuilder.Append('",')
    [void]$StringBuilder.Append('"Message":"');      [void]$StringBuilder.Append((ConvertTo-JsonEscapedString $Message));      [void]$StringBuilder.Append('",')
    [void]$StringBuilder.Append('"Timer":');         [void]$StringBuilder.Append($Timer);                                      [void]$StringBuilder.Append(',')
    [void]$StringBuilder.Append('"Attempts":');      [void]$StringBuilder.Append($Attempts);                                   [void]$StringBuilder.Append(',')
    [void]$StringBuilder.Append('"Test":');          [void]$StringBuilder.Append($(if($Test){'true'}else{'false'}));           [void]$StringBuilder.Append(',')
    [void]$StringBuilder.Append('"WorkDir":"');      [void]$StringBuilder.Append((ConvertTo-JsonEscapedString $WorkDir));      [void]$StringBuilder.Append('",')
    [void]$StringBuilder.Append('"Log":"');          [void]$StringBuilder.Append((ConvertTo-JsonEscapedString $Log));          [void]$StringBuilder.Append('",')
    [void]$StringBuilder.Append('"Items":[')
    for ($i=0; $i -lt $DetectedProcesses.Count; $i++) {
        $it = $DetectedProcesses[$i]; if ($i -gt 0) { [void]$StringBuilder.Append(',') }
        [void]$StringBuilder.Append('{')
        [void]$StringBuilder.Append('"Name":"');        [void]$StringBuilder.Append((ConvertTo-JsonEscapedString $it.Name));        [void]$StringBuilder.Append('",')
        [void]$StringBuilder.Append('"ShortName":"');   [void]$StringBuilder.Append((ConvertTo-JsonEscapedString $it.ShortName));   [void]$StringBuilder.Append('",')
        [void]$StringBuilder.Append('"Description":"'); [void]$StringBuilder.Append((ConvertTo-JsonEscapedString $it.Description)); [void]$StringBuilder.Append('",')
        [void]$StringBuilder.Append('"ExePath":"');     [void]$StringBuilder.Append((ConvertTo-JsonEscapedString $it.ExePath));     [void]$StringBuilder.Append('",')
        [void]$StringBuilder.Append('"IconBase64":"');  [void]$StringBuilder.Append((ConvertTo-JsonEscapedString $it.IconBase64));  [void]$StringBuilder.Append('"')
        [void]$StringBuilder.Append('}')
    }
    [void]$StringBuilder.Append(']}')
    return $StringBuilder.ToString()
}

function Write-Json([string]$WorkDir,[string]$Product,[string]$Payload){
    # Writes JSON beside log if possible, otherwise under WorkDir. Returns full path.
    $jsonPath = [IO.Path]::ChangeExtension($script:LogPath, ".json")
    try {
        $enc = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($jsonPath,$Payload,$enc)
        Write-CustomLog ("JSON feed written: " + $jsonPath + " (length=" + $Payload.Length + ")")
    } catch {
        Write-CustomLog ("ERROR writing JSON: " + $_.Exception.Message)
        Stop-Script 4
    }
    return $jsonPath
}

function Read-Json([string]$Path){
    <#
        Purpose:
          Read the persisted JSON file and reconstruct the minimal state needed for a fast relaunch.
          ConvertFrom-Json is not available in PowerShell v2, so there is a tiny parser.
          We only parse the fields we write, anything else is ignored.
        Expected JSON layout:
          {
            "Product":"...","Message":"...", "Timer":123, "Attempts":8, "Test":true,
            "WorkDir":"...", "Log":"...",
            "Items":[
              {"Name":"...","ShortName":"...","Description":"...","ExePath":"...","IconBase64":"..."}
            ]
          }
    #>
    # ---------- Read file ----------
    $jsonText = $null
    try { $jsonText = [IO.File]::ReadAllText($Path,[Text.Encoding]::UTF8) }
    catch { Write-CustomLog ("ERROR: reading JSON: " + $_.Exception.Message); return $null }
    if ([string]::IsNullOrEmpty($jsonText)) { Write-CustomLog "JSON is empty."; return $null }
    # ---------- Result object skeleton ----------
    $state = @{Product=$null;Message=$null;Timer=$null;Attempts=$null;Test=$false;WorkDir=$null;Log=$null;Items=@()}
    # ---------- JSON unescape for strings ----------
    function ConvertTo-UnescapeString([string]$escapedInput){
        if ($null -eq $escapedInput) { return $null }
        # Build output progressively to avoid repeated string reallocations.
        $stringBuilder = New-Object System.Text.StringBuilder
        for ($currentIndex = 0; $currentIndex -lt $escapedInput.Length; $currentIndex++) {
            $currentChar = $escapedInput[$currentIndex]
            if ($currentChar -ne '\') { [void]$stringBuilder.Append($currentChar); continue }  # fast path
            if ($currentIndex + 1 -ge $escapedInput.Length) { [void]$stringBuilder.Append('\'); break } # trailing '\'
            $currentIndex++
            $escapeChar = $escapedInput[$currentIndex]
            switch ($escapeChar) {
                '"' { [void]$stringBuilder.Append('"') }
                '\' { [void]$stringBuilder.Append('\') }
                '/' { [void]$stringBuilder.Append('/') }
                'b' { [void]$stringBuilder.Append([char]8) }     # backspace
                'f' { [void]$stringBuilder.Append([char]12) }    # form feed
                'n' { [void]$stringBuilder.Append("`n") }
                'r' { [void]$stringBuilder.Append("`r") }
                't' { [void]$stringBuilder.Append("`t") }
                'u' {
                    # Unicode escape: expect exactly 4 hex digits after \u
                    if ($currentIndex + 4 -lt $escapedInput.Length) {
                        $unicodeHex = $escapedInput.Substring($currentIndex + 1, 4)
                        $unicodeCodePoint = 0
                        if ([int]::TryParse($unicodeHex,
                                            [System.Globalization.NumberStyles]::HexNumber,
                                            [System.Globalization.CultureInfo]::InvariantCulture,
                                            [ref]$unicodeCodePoint)) {
                            [void]$stringBuilder.Append([char]$unicodeCodePoint)
                            $currentIndex += 4
                        } else {
                            # Invalid \u sequence -> write literally
                            [void]$stringBuilder.Append('\u')
                        }
                    } else {
                        # Not enough characters left for \uXXXX -> write literally
                        [void]$stringBuilder.Append('\u')
                    }
                }
                default { [void]$stringBuilder.Append($escapeChar) } # Unknown escape -> literal
            }
        }
        return $stringBuilder.ToString()
    }
    # ---------- Path normalization right after unescape ----------
    function ConvertTo-NormalizedPath([string]$escapedPath){
        # Purpose: convert over-escaped JSON path (e.g., C:\\\\...) into a clean Windows path (C:\...).
        if ([string]::IsNullOrEmpty($escapedPath)) { return $null }
        $unescaped = ConvertTo-UnescapeString $escapedPath
        if ([string]::IsNullOrEmpty($unescaped)) { return $unescaped }
        $normalized = $unescaped.Trim().Trim('"')
        # Collapse any run of slashes/backslashes into a single backslash.
        $normalized = $normalized -replace '[\\/]+','\'
        # Try to resolve to a full canonical path when possible.
        try { $normalized = [IO.Path]::GetFullPath($normalized) } catch { }
        return $normalized
    }
    # ---------- Parse top-level scalar/string fields ----------
    foreach ($fieldName in 'Product','Message') {
        if ($jsonText -match '"' + [Regex]::Escape($fieldName) + '":"([^"]*)"') {
            $state[$fieldName] = ConvertTo-UnescapeString $matches[1]
        }
    }
    # Paths: unescape + normalize to avoid doubled backslashes
    if ($jsonText -match '"WorkDir":"([^"]*)"')    { $state['WorkDir']  = ConvertTo-NormalizedPath $matches[1] }
    if ($jsonText -match '"Log":"([^"]*)"')        { $state['Log']      = ConvertTo-NormalizedPath $matches[1] }
    if ($jsonText -match '"Timer":\s*([0-9]+)')    { $state['Timer']    = [int]$matches[1] }
    if ($jsonText -match '"Attempts":\s*([0-9]+)') { $state['Attempts'] = [int]$matches[1] }
    if ($jsonText -match '"Test":\s*(true|false)') { $state['Test']     = ($matches[1] -eq 'true') }
    # ---------- Parse Items array ----------
    if ($jsonText -match '"Items":\s*\[(.*)\]') {
        $itemsArrayBlob = $matches[1]
        $rawItemChunks = @()
        if ($itemsArrayBlob -notmatch '^\s*$') { $rawItemChunks = $itemsArrayBlob -split '\},\s*\{' } else { $rawItemChunks = @() }
        foreach ($rawItem in $rawItemChunks) {
            $cleanChunk = $rawItem.Trim(@([char]'{',[char]'}',[char]' '))
            $item = @{
                Name        = $null
                ShortName   = $null
                Description = $null
                ExePath     = $null
                IconBase64  = $null
                Process_Ids = @()
            }
            if ($cleanChunk -match '"Name":"([^"]*)"')        { $item.Name        = ConvertTo-UnescapeString $matches[1] }
            if ($cleanChunk -match '"ShortName":"([^"]*)"')   { $item.ShortName   = ConvertTo-UnescapeString $matches[1] }
            if ($cleanChunk -match '"Description":"([^"]*)"') { $item.Description = ConvertTo-UnescapeString $matches[1] }
            if ($cleanChunk -match '"ExePath":"([^"]*)"')     { $item.ExePath     = ConvertTo-NormalizedPath $matches[1] }
            if ($cleanChunk -match '"IconBase64":"([^"]*)"')  { $item.IconBase64  = ConvertTo-UnescapeString $matches[1] }
            $state.Items += ,$item
        }
    }
    return $state
}


# ==================================================================
#                           FrontEnd STARTERS
# ==================================================================

function Start-FromCurrentUser([string]$Pwsh,[string]$ArgumentsLine,[switch]$ShowWindow) {
    # Launch FrontEnd in current interactive session and wait
    Write-CustomLog ("Launching FrontEnd in current session (console " + ($(if($ShowWindow){"visible"}else{"hidden"})) + ")...")
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName       = $Pwsh
        $psi.Arguments      = $ArgumentsLine
        $psi.UseShellExecute= $false
        $psi.CreateNoWindow = (-not $ShowWindow)
        $psi.WindowStyle    = $(if($ShowWindow){ [System.Diagnostics.ProcessWindowStyle]::Normal } else { [System.Diagnostics.ProcessWindowStyle]::Hidden })
        $p = [System.Diagnostics.Process]::Start($psi); $p.WaitForExit()
        Write-CustomLog ("FrontEnd exited with code " + $p.ExitCode)
        return @{ Success=$true; ExitCode=$p.ExitCode; Process_Id=$p.Id }
    } catch { Write-CustomLog ("ERROR: Start-Process/Wait-Process failed: " + $_.Exception.Message); return @{ Success=$false; ExitCode=$null; Process_Id=$null } }
}

function Start-FromSystemAsCurrentUser {
    <#
        Launch a process in the interactive user's session to show UI while the caller is running as system
          - Build user environment block
          - CreateProcessAsUser with proper flags
          - Wait for process completion and capture exit code
          - Clean up all native handles
        Returns:
          Hashtable: @{ Success=bool; ExitCode=int|null; Process_Id=int|null; Win32Error=int|null }
    #>
    [CmdletBinding(DefaultParameterSetName='BySession')]
    param(
        [Parameter(Mandatory=$true)]                               [string]$ExePath,
        [Parameter(Mandatory=$true)]                               [string]$ArgumentsLine,
        [Parameter(Mandatory=$false)]                              [string]$WorkingDir = $(Split-Path -Path $ExePath -Parent),
        [Parameter(Mandatory=$false)]                              [switch]$ShowWindow,
        # Option 1: start from a SessionId -> the function will do WTSQueryUserToken + DuplicateTokenEx
        [Parameter(Mandatory=$true, ParameterSetName='BySession')] [int]$SessionId,
        # Option 2: start from an already provided PRIMARY token
        [Parameter(Mandatory=$true, ParameterSetName='ByToken')]   [IntPtr]$PrimaryToken
    )
    function Enable-Privilege([string]$PrivilegeName) {
        # Enables a given privilege on the current process token
        $TOKEN_ADJUST_PRIVILEGES = 0x20
        $TOKEN_QUERY             = 0x8
        $SE_PRIVILEGE_ENABLED    = 0x2
        $currentProcessHandle = [Kernel32]::GetCurrentProcess()
        $processTokenHandle  = [IntPtr]::Zero
        if (-not [AdvApi32]::OpenProcessToken($currentProcessHandle,$TOKEN_ADJUST_PRIVILEGES -bor $TOKEN_QUERY,[ref]$processTokenHandle)) { Write-CustomLog ("WARN: OpenProcessToken failed " + [Runtime.InteropServices.Marshal]::GetLastWin32Error()); return $false }
        try {
            $locallyUniqueId = New-Object LUID
            if (-not [AdvApi32]::LookupPrivilegeValue($null,$PrivilegeName,[ref]$locallyUniqueId)) { Write-CustomLog ("WARN: LookupPrivilegeValue(" + $PrivilegeName + ") failed " + [Runtime.InteropServices.Marshal]::GetLastWin32Error()); return $false }
            $luidAndAttributes = New-Object LUID_AND_ATTRIBUTES
            $luidAndAttributes.Luid = $locallyUniqueId; $luidAndAttributes.Attributes = $SE_PRIVILEGE_ENABLED
            $tokenPrivileges = New-Object TOKEN_PRIVILEGES
            $tokenPrivileges.PrivilegeCount = 1; $tokenPrivileges.Privileges = $luidAndAttributes
            if (-not [AdvApi32]::AdjustTokenPrivileges($processTokenHandle,$false,[ref]$tokenPrivileges,0,[IntPtr]::Zero,[IntPtr]::Zero)) { Write-CustomLog ("WARN: AdjustTokenPrivileges(" + $PrivilegeName + ") failed " + [Runtime.InteropServices.Marshal]::GetLastWin32Error()); return $false }
            Write-CustomLog ("Privilege enabled: " + $PrivilegeName); return $true
        } finally { if ($processTokenHandle -ne [IntPtr]::Zero) { [Kernel32]::CloseHandle($processTokenHandle) | Out-Null } }
    }
    function Get-TokenUser([IntPtr]$UserTokenHandle) {
        # Uses GetTokenInformation(TOKEN_USER) and LookupAccountSid to return 'Domain\Name' for a token.
        $allocatedBuffer = [IntPtr]::Zero
        try {
            $requiredLength = 0
            [AdvApi32]::GetTokenInformation($UserTokenHandle,1,[IntPtr]::Zero,0,[ref]$requiredLength) | Out-Null
            if ($requiredLength -le 0) { return "Unknown" }
            $allocatedBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($requiredLength)
            if ([AdvApi32]::GetTokenInformation($UserTokenHandle,1,$allocatedBuffer,$requiredLength,[ref]$requiredLength)) {
                $sidPointer = [Runtime.InteropServices.Marshal]::ReadIntPtr($allocatedBuffer)
                $accountNameBuilder = New-Object Text.StringBuilder 256
                $domainNameBuilder  = New-Object Text.StringBuilder 256
                $accountNameCapacity = [uint32]$accountNameBuilder.Capacity
                $domainNameCapacity  = [uint32]$domainNameBuilder.Capacity
                $sidUse = 0
                if ([AdvApi32]::LookupAccountSid($null,$sidPointer,$accountNameBuilder,[ref]$accountNameCapacity,$domainNameBuilder,[ref]$domainNameCapacity,[ref]$sidUse)) {
                    return ($domainNameBuilder.ToString() + "\" + $accountNameBuilder.ToString())
                }
            }
        } catch { Write-CustomLog ("Error getting token user: " + $_.Exception.Message) }
        finally { if ($allocatedBuffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($allocatedBuffer) } }
        "Unknown"
    }
    # Standardized return structure
    $result = @{ Success = $false; ExitCode = $null; Process_Id = $null; Win32Error = $null }
    # Native handles
    $userTokenHandle               = [IntPtr]::Zero  # Impersonation token returned by WTSQueryUserToken
    $duplicatedPrimaryTokenHandle  = [IntPtr]::Zero  # Primary token obtained via DuplicateTokenEx
    $tokenForCreateProcess         = [IntPtr]::Zero  # Token passed to CreateProcessAsUser
    $environmentBlockPointer       = [IntPtr]::Zero  # Pointer returned by CreateEnvironmentBlock
    try {
        # If we start from a SessionId, do the whole SYSTEM -> user token pipeline here
        if ($PSCmdlet.ParameterSetName -eq 'BySession') {
            # 1) Ensure the SYSTEM process has the privileges typically required to launch in user session
            [void](Enable-Privilege "SeIncreaseQuotaPrivilege")
            [void](Enable-Privilege "SeAssignPrimaryTokenPrivilege")
            # 2) Obtain an impersonation token for the interactive user in the given session
            Write-CustomLog ("Calling WTSQueryUserToken for session " + $SessionId + "...")
            if (-not [WtsApi32]::WTSQueryUserToken($SessionId,[ref]$userTokenHandle)) {
                $lastWin32Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $result.Win32Error = $lastWin32Error
                Write-CustomLog ("ERROR: WTSQueryUserToken failed: " + $lastWin32Error)
                return $result
            }
            Write-CustomLog ("WTSQueryUserToken OK. Token belongs to: " + (Get-TokenUser $userTokenHandle))
            # 3) Duplicate to a PRIMARY token because CreateProcessAsUser requires a primary token
            $TOKEN_ALL_ACCESS        = 0xF01FF
            $SecurityImpersonation   = 2
            $TokenTypePrimary        = 1
            Write-CustomLog "Calling DuplicateTokenEx..."
            if (-not [AdvApi32]::DuplicateTokenEx(
                    $userTokenHandle,
                    $TOKEN_ALL_ACCESS,
                    [IntPtr]::Zero,
                    $SecurityImpersonation,
                    $TokenTypePrimary,
                    [ref]$duplicatedPrimaryTokenHandle)) {
                $lastWin32Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $result.Win32Error = $lastWin32Error
                Write-CustomLog ("ERROR: DuplicateTokenEx failed: " + $lastWin32Error)
                return $result
            }
            $tokenForCreateProcess = $duplicatedPrimaryTokenHandle
        }
        else {
            # ByToken parameter set: the caller provides a PRIMARY token already
            if ($PrimaryToken -eq [IntPtr]::Zero) {
                Write-CustomLog "ERROR: Start-FromSystemAsCurrentUser called with NULL PrimaryToken."
                return $result
            }
            $tokenForCreateProcess = $PrimaryToken
        }
        # Build the user environment block
        try { [UserEnv]::CreateEnvironmentBlock([ref]$environmentBlockPointer,$tokenForCreateProcess,$false) | Out-Null } catch {}
        # Prepare STARTUPINFO (windowing) and creation flags
        $startupInfo = New-Object STARTUPINFO
        $startupInfo.cb = [Runtime.InteropServices.Marshal]::SizeOf([type]([STARTUPINFO]))
        $startupInfo.lpDesktop = 'winsta0\default'
        if ($ShowWindow) { $startupInfo.dwFlags = 0x1; $startupInfo.wShowWindow = 1 } else { $startupInfo.dwFlags = 0 }
        $CREATE_NO_WINDOW            = 0x08000000
        $CREATE_NEW_CONSOLE          = 0x00000010
        $CREATE_UNICODE_ENVIRONMENT  = 0x00000400
        $CREATE_BREAKAWAY_FROM_JOB   = 0x01000000
        $creationFlags = $(if($ShowWindow){ $CREATE_NEW_CONSOLE } else { $CREATE_NO_WINDOW })
        if ($environmentBlockPointer -ne [IntPtr]::Zero) { $creationFlags = $creationFlags -bor $CREATE_UNICODE_ENVIRONMENT }
        $creationFlags = $creationFlags -bor $CREATE_BREAKAWAY_FROM_JOB
        # Build the command line string that will be passed to CreateProcessAsUser
        $fullCommandLine = (Format-CommandLineArgument $ExePath) + ' ' + $ArgumentsLine
        Write-CustomLog ("Executable path: " + $ExePath)
        Write-CustomLog ("Arguments: " + $ArgumentsLine)
        Write-CustomLog ("Working dir: " + $WorkingDir)
        Write-CustomLog ("Calling CreateProcessAsUser (console " + ($(if($ShowWindow){"visible"}else{"hidden"})) + ")...")
        # Perform the actual process creation in the user's session
        $processInformation = New-Object PROCESS_INFORMATION
        $createOk = [AdvApi32]::CreateProcessAsUser(
            $tokenForCreateProcess, $ExePath, $fullCommandLine,
            [IntPtr]::Zero, [IntPtr]::Zero, $false,
            $creationFlags, $environmentBlockPointer, $WorkingDir,
            [ref]$startupInfo, [ref]$processInformation
        )
        # Destroy the environment block if we created one
        if ($environmentBlockPointer -ne [IntPtr]::Zero) { try { [UserEnv]::DestroyEnvironmentBlock($environmentBlockPointer) | Out-Null } catch {} }
        if (-not $createOk) {
            $lastWin32Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $result.Win32Error = $lastWin32Error
            Write-CustomLog ("ERROR: CreateProcessAsUser failed with " + $lastWin32Error)
            switch ($lastWin32Error) {
                2   { Write-CustomLog "  Error 2: File not found" }
                3   { Write-CustomLog "  Error 3: Path not found" }
                5   { Write-CustomLog "  Error 5: Access denied" }
                87  { Write-CustomLog "  Error 87: Bad parameter" }
                123 { Write-CustomLog "  Error 123: Bad filename/dir syntax" }
                1314{ Write-CustomLog "  Error 1314: Missing privilege" }
                740 { Write-CustomLog "  Error 740: Requires elevation" }
                default { Write-CustomLog "  Unknown error" }
            }
            return $result
        }
        Write-CustomLog ("SUCCESS: Process_Id=" + $processInformation.dwProcessId + " TID=" + $processInformation.dwThreadId)
        $result.Process_Id = $processInformation.dwProcessId
        # Wait for the child process to finish and capture its exit code
        try {
            $WAIT_INFINITE  = [uint32]::MaxValue
            $WAIT_OBJECT_0  = [uint32]0
            $waitResult = [Kernel32]::WaitForSingleObject($processInformation.hProcess, $WAIT_INFINITE)
            if ($waitResult -eq $WAIT_OBJECT_0) {
                $exitCodeValue = 0
                if ([Kernel32]::GetExitCodeProcess($processInformation.hProcess, [ref]$exitCodeValue)) {
                    Write-CustomLog ("FrontEnd exited with code " + $exitCodeValue)
                    $result.ExitCode = [int]$exitCodeValue
                } else {
                    $lastWin32Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    $result.Win32Error = $lastWin32Error
                    Write-CustomLog ("GetExitCodeProcess failed (GLE=" + $lastWin32Error + ").")
                }
            } else {
                $lastWin32Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $result.Win32Error = $lastWin32Error
                Write-CustomLog ("WaitForSingleObject returned " + $waitResult + " (GLE=" + $lastWin32Error + "). Proceeding without exit code.")
            }
        } catch {
            Write-CustomLog ("WARNING: waiting for FrontEnd failed: " + $_.Exception.Message)
        } finally {
            if ($processInformation.hThread  -ne [IntPtr]::Zero) { [Kernel32]::CloseHandle($processInformation.hThread)  | Out-Null }
            if ($processInformation.hProcess -ne [IntPtr]::Zero) { [Kernel32]::CloseHandle($processInformation.hProcess) | Out-Null }
        }
        $result.Success = $true
        return $result
    }
    finally {
        # Always close any handles we opened inside this function
        if ($userTokenHandle -ne [IntPtr]::Zero)              { [Kernel32]::CloseHandle($userTokenHandle)             | Out-Null }
        if ($duplicatedPrimaryTokenHandle -ne [IntPtr]::Zero) { [Kernel32]::CloseHandle($duplicatedPrimaryTokenHandle)| Out-Null }
        # Do NOT close $PrimaryToken if it was provided by the caller (ByToken set).
    }
}

function Invoke-ViaSystemScheduledTaskAndWait {
    <#
      Relaunch this backend as SYSTEM via a one-shot Task Scheduler COM task, passing only -JsonPath.
      Uses COM end-to-end (no schtasks.exe): register/replace -> run -> poll -> fetch exit code -> cleanup.
      Returns: @{ Success = <bool>; ExitCode = <int or $null> }
    #>
    param([string]$ScriptPath,[string]$JsonPath,[int]$TimeoutSeconds=600)

    # --- Helper: copy backend script in UTF-8 BOM
    function Copy-ScriptUtf8Bom([string]$SourcePath,[string]$DestinationPath){
        try {
            $utf8WithBom = New-Object System.Text.UTF8Encoding $true
            [System.IO.File]::WriteAllText($DestinationPath,(Get-Content -LiteralPath $SourcePath -Raw),$utf8WithBom)
            Write-CustomLog ("Task helper: backend copied (UTF-8 BOM) to " + $DestinationPath)
            return $DestinationPath
        } catch {
            Write-CustomLog ("ERROR: backend copy failed: " + $_.Exception.Message)
            return $null
        }
    }
    # --- Helper: connect to Task Scheduler and get the root folder
    function Open-TaskSchedulerRoot(){
        $serviceCom = $null; $rootFolderCom = $null
        try { $serviceCom = New-Object -ComObject 'Schedule.Service'; $serviceCom.Connect(); $rootFolderCom = $serviceCom.GetFolder("\") }
        catch { Write-CustomLog ("ERROR: Task Scheduler COM connection failed: " + $_.Exception.Message) }
        return @{ Service=$serviceCom; Root=$rootFolderCom }
    }
    # --- Helper: delete task if exists, stop first if running
    function Remove-TaskIfExists($rootFolderCom,[string]$TaskName){
        if (-not $rootFolderCom) { return }
        $registeredTask = $null
        try { $registeredTask = $rootFolderCom.GetTask("\$TaskName") } catch { $registeredTask = $null }
        if ($registeredTask) {
            Write-CustomLog ("Existing task '" + $TaskName + "' found -> stopping and deleting...")
            try { $registeredTask.Stop(0) } catch {}
            Start-Sleep -Milliseconds 300
            $deleted=$false; for($r=1;$r -le 5 -and -not $deleted;$r++){ try { $rootFolderCom.DeleteTask($TaskName,0) | Out-Null; $deleted=$true } catch { Start-Sleep -Milliseconds 200 } }
            if ($deleted) { Write-CustomLog ("Existing task '" + $TaskName + "' deleted.") } else { Write-CustomLog ("WARN: Could not delete existing task '" + $TaskName + "'.") }
        }
    }

    # --- Helper: register a one-shot on-demand SYSTEM task with Exec action.
    function Register-SystemTaskCom($rootFolderCom,[string]$TaskName,[string]$ExecutablePath,[string]$ArgumentsLine,[string]$WorkingDirectory,[int]$TimeoutSeconds){
        if (-not $rootFolderCom) { return $null }
        # COM constants
        $TASK_CREATE_OR_UPDATE=6; $TASK_LOGON_SERVICE_ACCOUNT=5; $TASK_RUNLEVEL_HIGHEST=1; $TASK_ACTION_EXEC=0
        try {
            $taskDefinition = $rootFolderCom.GetFolder("\").Parent.NewTask(0)
        } catch {
            # Fallback to service from root if Parent is not exposed (varies by host)
            try {
                $service = New-Object -ComObject 'Schedule.Service'; $service.Connect(); $taskDefinition = $service.NewTask(0)
            } catch { Write-CustomLog ("ERROR: NewTask failed: " + $_.Exception.Message); return $null }
        }
        function Convert-SecondsToIso([int]$TotalSeconds){
            if ($TotalSeconds -le 0) { return 'PT0S' }  # infinite
            $remaining = [int]$TotalSeconds
            $hours = [Math]::Floor($remaining / 3600); $remaining = $remaining % 3600
            $minutes = [Math]::Floor($remaining / 60);  $remaining = $remaining % 60
            $seconds = $remaining
            $duration = 'PT'
            if ($hours   -gt 0) { $duration += ($hours.ToString()   + 'H') }
            if ($minutes -gt 0) { $duration += ($minutes.ToString() + 'M') }
            if ($seconds -gt 0 -or $duration -eq 'PT') { $duration += ($seconds.ToString() + 'S') }
            return $duration
        }
        try {
            $taskDefinition.RegistrationInfo.Description = "Temporary SYSTEM relaunch for CloseProcessPopup backend"
            $taskDefinition.Principal.UserId    = "SYSTEM"
            $taskDefinition.Principal.LogonType = $TASK_LOGON_SERVICE_ACCOUNT
            $taskDefinition.Principal.RunLevel  = $TASK_RUNLEVEL_HIGHEST
            $settings = $taskDefinition.Settings
            $settings.AllowDemandStart           = $true
            $settings.StartWhenAvailable         = $true
            $settings.DisallowStartIfOnBatteries = $false
            $settings.StopIfGoingOnBatteries     = $false
            $settings.RunOnlyIfIdle              = $false
            $settings.RunOnlyIfNetworkAvailable  = $false
            $settings.MultipleInstances          = 0
            $settings.ExecutionTimeLimit         = if ($TimeoutSeconds) {Convert-SecondsToIso $($TimeoutSeconds+60) } else {"PT0S"}
            $settings.Hidden                     = $false
            $settings.Enabled                    = $true
            $execAction = $taskDefinition.Actions.Create($TASK_ACTION_EXEC)
            $execAction.Path      = $ExecutablePath
            $execAction.Arguments = $ArgumentsLine
            if ($WorkingDirectory) { $execAction.WorkingDirectory = $WorkingDirectory }
            $null = $rootFolderCom.RegisterTaskDefinition("\$TaskName",$taskDefinition,$TASK_CREATE_OR_UPDATE,$null,$null,$TASK_LOGON_SERVICE_ACCOUNT,$null)
            Write-CustomLog ("Task registered via COM: '" + $TaskName + "' (Exec='" + $ExecutablePath + "')")
            $registeredTask = $rootFolderCom.GetTask("\$TaskName")
            return $registeredTask
        } catch { Write-CustomLog ("ERROR: COM task registration failed: " + $_.Exception.Message); return $null }
    }
    # --- Helper: run the task now; return LastRunTime before launch and the IRegisteredTask.
    function Start-TaskCom($rootFolderCom,[string]$TaskName){
        $registeredTask = $null; try { $registeredTask = $rootFolderCom.GetTask("\$TaskName") } catch {}
        if (-not $registeredTask) { Write-CustomLog ("ERROR: RegisteredTask fetch failed for '" + $TaskName + "'."); return @{ Task=$null; LastRunBefore=$null } }
        $lastRunBefore=$null; try { $lastRunBefore = $registeredTask.LastRunTime } catch {}
        try { $registeredTask.Run($null) | Out-Null } catch { Write-CustomLog ("ERROR: Task.Run failed: " + $_.Exception.Message) }
        return @{ Task=$registeredTask; LastRunBefore=$lastRunBefore }
    }
    # --- Helper: wait until task is no longer Running and LastRunTime advanced
    function Wait-TaskCompletionCom($registeredTask,[datetime]$lastRunBefore,[int]$timeoutSec){
        $deadline = (Get-Date).AddSeconds($timeoutSec)
        while ((Get-Date) -lt $deadline) {
            $state=$null; $lastRun=$null; $lastResult=$null
            try { $state=$registeredTask.State; $lastRun=$registeredTask.LastRunTime; $lastResult=$registeredTask.LastTaskResult } catch { Start-Sleep 1; continue }
            $finished = ($state -ne 4) -and ((-not $lastRunBefore) -or ($lastRun -gt $lastRunBefore))
            if ($finished) { return $lastResult }
            Start-Sleep 1
        }
        return $null
    }
    # --- Helper: delete task and remove temporary script.
    function Remove-TaskAndFile($rootFolderCom,[string]$TaskName,[string]$TempBackendPath){
        try { 
            if ($rootFolderCom   -and $TaskName) { 
                $rootFolderCom.DeleteTask($TaskName,0) | Out-Null 
            }
        } catch {Write-CustomLog "WARN: Cannot delete Task '$TaskName'"}
    }

    # ============================= Main sequence (COM-only) =============================
    $powerShellExePath = Resolve-PwshExe
    $copiedBackendPath = Copy-ScriptUtf8Bom -SourcePath $ScriptPath -DestinationPath "$WorkDir\CloseProcessPopup.ps1"
    if (-not $copiedBackendPath) { return @{ Success=$false; ExitCode=$null } }

    # Build Exec path + arguments
    $execPath      = $powerShellExePath
    $argumentsLine = ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -JsonPath "{1}" -Log "{2}"' -f $copiedBackendPath,$JsonPath,$script:LogPath)
    $workingOfExec = Split-Path -Path $powerShellExePath -Parent

    # Connect COM root and register a task (replace if exist)
    $com = Open-TaskSchedulerRoot
    if (-not $com.Root) { try { Remove-Item -LiteralPath $copiedBackendPath -Force -ErrorAction SilentlyContinue } catch {}; return @{ Success=$false; ExitCode=$null } }
    $taskName = "[Temp]_CloseProcessPopup_FrontEnd"
    Remove-TaskIfExists -rootFolderCom $com.Root -TaskName $taskName
    $registeredTask = Register-SystemTaskCom -rootFolderCom $com.Root -TaskName $taskName -ExecutablePath $execPath -ArgumentsLine $argumentsLine -WorkingDirectory $workingOfExec -TimeoutSeconds $TimeoutSeconds
    if (-not $registeredTask) { Remove-TaskAndFile -rootFolderCom $com.Root -TaskName $taskName -TempBackendPath $copiedBackendPath; return @{ Success=$false; ExitCode=$null } }

    # Run and wait for completion via COM polling.
    $runCtx = Start-TaskCom -rootFolderCom $com.Root -TaskName $taskName
    if (-not $runCtx.Task) { Remove-TaskAndFile -rootFolderCom $com.Root -TaskName $taskName -TempBackendPath $copiedBackendPath; return @{ Success=$false; ExitCode=$null } }
    Write-CustomLog "SYSTEM task started; waiting for completion via Task Scheduler COM..."
    $exitCode = Wait-TaskCompletionCom -registeredTask $runCtx.Task -lastRunBefore $runCtx.LastRunBefore -timeoutSec $($TimeoutSeconds + 120)

    # Cleanup and return status.
    Remove-TaskAndFile -rootFolderCom $com.Root -TaskName $taskName -TempBackendPath $copiedBackendPath
    if ($null -eq $exitCode) { Write-CustomLog "Timeout or unknown state while waiting for SYSTEM task (COM polling)."; return @{ Success=$false; ExitCode=$null } }
    Write-CustomLog ("SYSTEM task finished with ExitCode=" + [int]$exitCode)
    return @{ Success = ([int]$exitCode -eq 0); ExitCode = [int]$exitCode }
}


# ==================================================================
#                             MAIN FLOW
# ==================================================================

# If -JsonPath is provided and exists, shortcut: reconstruct state and jump to launch strategy
$stateFromJson = $FrontEndpath = $null
if ($JsonPath -and (Test-Path -LiteralPath $JsonPath -PathType Leaf)) {
    $script:LogPath = $Log
    $script:LogName = Format-Name ([IO.Path]::GetFileNameWithoutExtension($script:LogPath))
    Write-CustomLog "========================================="
    Write-CustomLog "Starting BACKEND with JSON - $LogName"
    Write-CustomLog "========================================="
    Write-CustomLog ("Restoring state from " + $JsonPath)
    $stateFromJson = Read-Json -Path $JsonPath
    if ($null -ne $stateFromJson) {
        if ($stateFromJson.Product)        { $Product  = $stateFromJson.Product }
        if ($null -ne $stateFromJson.Message) { $Message  = $stateFromJson.Message }
        if ($null -ne $stateFromJson.Timer)   { $Timer    = [int]$stateFromJson.Timer }
        if ($null -ne $stateFromJson.Attempts){ $Attempts = [int]$stateFromJson.Attempts }
        if ($stateFromJson.WorkDir)        { $WorkDir  = $stateFromJson.WorkDir }
        if ($stateFromJson.Log)            { $Log      = $stateFromJson.Log; $script:LogPath = $Log }
        if ($stateFromJson.Test -eq $true) { $Test     = $true } else { if ($Test) { } } # keep console showed if -Test is present
        $DetectedProcesses = $stateFromJson.Items
        $FrontEndpath = Join-Path $WorkDir "CloseProcessPopup_FrontEnd.ps1"
    } else {
        Write-CustomLog "WARN: failed to restore state from JSON. Proceeding with normal discovery."
        $JsonPath = $null
    }
}
# If no JsonPath (or restore failed), do process discovery and write JSON
else {
    $Product        = Format-Name $Product
    $WorkDir        = Resolve-WorkDir $WorkDir
    $null           = Resolve-LogPath -WorkDir $WorkDir -Product $Product -CandidateLog $Log
    $script:LogName = Format-Name ([IO.Path]::GetFileNameWithoutExtension($script:LogPath))
    $FrontEndpath   = Join-Path $WorkDir "CloseProcessPopup_FrontEnd.ps1"
    Write-CustomLog "========================================="
    Write-CustomLog "Starting BACKEND"
    Write-CustomLog "========================================="
    $principalInfo = Get-SessionContext
    Write-CustomLog ("Current user    : " + $principalInfo.Name)
    Write-CustomLog ("Is System       : " + $principalInfo.IsSystem)
    Write-CustomLog ("Is Administrator: " + $principalInfo.IsAdmin)
    $DetectedProcesses = Get-RunningProcesses -Processes $Process -ProcessesPaths $ProcessPath

    ###############################  Write FrontEnd PS1 script  ###############################
    $frontContent = @'
#requires -version 2.0
Param(
    [Parameter(Mandatory=$true)]  [string]$JsonPath,
    [Parameter(Mandatory=$true)]  [string]$Log
)

# ----- Optional sidebar logo base64 (will be rotated 90° left) -----
[string]$SidebarLogoBase64 = ""

# ------------------------- Logging -------------------------
function Write-FrontEndLog {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "$ts - [FrontEnd] - $Message"
    try {
        $sw = New-Object IO.StreamWriter($Log,$true,[Text.Encoding]::UTF8)
        $sw.WriteLine($line)
    } catch {} finally { if ($sw){$sw.Close()} }
    Write-Host $line
}

trap {
    Write-FrontEndLog "UNHANDLED ERROR: $($_.Exception.Message)"
    continue
}

Write-FrontEndLog "=== FrontEnd starting ==="

# Load core WinForms/GDI
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ----- Native helpers (DPI + regions + drag) -----
if (-not ('Win32Native' -as [type])) {
    Add-Type -ReferencedAssemblies System.Drawing,System.Windows.Forms -TypeDefinition @"
using System;
using System.Windows.Forms;
using System.Runtime.InteropServices;
public static class DPIHelper {
    public static readonly IntPtr DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE = new IntPtr(-3);
    [DllImport("user32.dll")] public static extern bool SetProcessDpiAwarenessContext(IntPtr dpiFlag);
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
"@
}
Write-FrontEndLog "Assemblies Loaded"
try { [DPIHelper]::SetProcessDpiAwarenessContext([DPIHelper]::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE) | Out-Null } catch {}
[System.Windows.Forms.Application]::EnableVisualStyles() | Out-Null

# ----- Localization -----
$IsFrenchUI = $false
try { $IsFrenchUI = ([System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName -eq 'fr') } catch { $IsFrenchUI = $false }
$TextResources = @{
    fr = @{ InstallingOf="Installation de "; DefaultInfo="Veuillez sauvegarder votre travail avant de continuer car les applications suivantes seront fermées automatiquement."; CountdownLabel="Compte à rebours avant fermeture automatique"; ActionButton="Fermer les applications et installer"; HourSuffix="h"; MinSuffix="m"; SecSuffix="s" }
    en = @{ InstallingOf="Installing "; DefaultInfo="Please save your work before continuing because the applications below will be closed automatically."; CountdownLabel="Countdown before automatic closing"; ActionButton="Close apps and install"; HourSuffix="h"; MinSuffix="m"; SecSuffix="s" }
}
$Locale = if ($IsFrenchUI) { $TextResources.fr } else { $TextResources.en }

# ----- Read & parse JSON payload from file -----
function Read-Json([string]$Path){
    # --- Read file ---
    $jsonText = $null
    try { $jsonText = [IO.File]::ReadAllText($Path,[Text.Encoding]::UTF8) }
    catch { Write-FrontEndLog ("ERROR: reading JSON: " + $_.Exception.Message); return $null }
    if ([string]::IsNullOrEmpty($jsonText)) { Write-FrontEndLog "ERROR: JSON is empty."; return $null }
    # --- Unescape "JSON string" → plain PowerShell string ---
    function ConvertTo-UnescapeString([string]$escapedInput){
        if ($null -eq $escapedInput) { return $null }
        # Build output progressively to avoid repeated string reallocations.
        $stringBuilder = New-Object System.Text.StringBuilder
        for ($currentIndex = 0; $currentIndex -lt $escapedInput.Length; $currentIndex++) {
            $currentChar = $escapedInput[$currentIndex]
            if ($currentChar -ne '\') { [void]$stringBuilder.Append($currentChar); continue }  # fast path
            if ($currentIndex + 1 -ge $escapedInput.Length) { [void]$stringBuilder.Append('\'); break } # trailing '\'
            $currentIndex++
            $escapeChar = $escapedInput[$currentIndex]
            switch ($escapeChar) {
                '"' { [void]$stringBuilder.Append('"') }
                '\' { [void]$stringBuilder.Append('\') }
                '/' { [void]$stringBuilder.Append('/') }
                'b' { [void]$stringBuilder.Append([char]8) }     # backspace
                'f' { [void]$stringBuilder.Append([char]12) }    # form feed
                'n' { [void]$stringBuilder.Append("`n") }
                'r' { [void]$stringBuilder.Append("`r") }
                't' { [void]$stringBuilder.Append("`t") }
                'u' {
                    # Unicode escape: expect exactly 4 hex digits after \u
                    if ($currentIndex + 4 -lt $escapedInput.Length) {
                        $unicodeHex = $escapedInput.Substring($currentIndex + 1, 4)
                        $unicodeCodePoint = 0
                        if ([int]::TryParse($unicodeHex,
                                            [System.Globalization.NumberStyles]::HexNumber,
                                            [System.Globalization.CultureInfo]::InvariantCulture,
                                            [ref]$unicodeCodePoint)) {
                            [void]$stringBuilder.Append([char]$unicodeCodePoint)
                            $currentIndex += 4
                        } else {
                            # Invalid \u sequence -> write literally
                            [void]$stringBuilder.Append('\u')
                        }
                    } else {
                        # Not enough characters left for \uXXXX -> write literally
                        [void]$stringBuilder.Append('\u')
                    }
                }
                default { [void]$stringBuilder.Append($escapeChar) } # Unknown escape -> literal
            }
        }
        return $stringBuilder.ToString()
    }
    # --- Parse top-level fields we need ---
    $product=$null;$message=$null;$timer=$null
    if ($jsonText -match '"Product"\s*:\s*"([^"]*)"') { $product = ConvertTo-UnescapeString $matches[1] }
    if ($jsonText -match '"Message"\s*:\s*"([^"]*)"') { $message = ConvertTo-UnescapeString $matches[1] }
    if ($jsonText -match '"Timer"\s*:\s*([0-9]+)')    { $timer   = [int]$matches[1] }
    # --- Parse Items[] (flat schema) ---
    $items=@()
    if ($jsonText -match '"Items"\s*:\s*\[(.*)\]'){
        $itemsBlob = $matches[1]
        if ($itemsBlob -notmatch '^\s*$'){
            $chunks = $itemsBlob -split '\},\s*\{'
            foreach($raw in $chunks){
                $chunk = $raw.Trim(@([char]'{',[char]'}',[char]' '))
                $name=$null;$desc=$null;$b64=$null;$exe=$null
                if ($chunk -match '"Name"\s*:\s*"([^"]*)"')        { $name = ConvertTo-UnescapeString $matches[1] }
                if ($chunk -match '"Description"\s*:\s*"([^"]*)"') { $desc = ConvertTo-UnescapeString $matches[1] }
                if ($chunk -match '"IconBase64"\s*:\s*"([^"]*)"')  { $b64  = ConvertTo-UnescapeString $matches[1] }
                $items += ,@{ Name=$name; Description=$desc; IconBase64=$b64 }
            }
        }
    }
    New-Object PSObject -Property @{ Product=$product; Message=$message; Timer=$timer; Items=$items }
}
# ====================== Get variables from JSON ======================
try {
    if (-not (Test-Path -LiteralPath $JsonPath -PathType Leaf)) { Write-FrontEndLog "ERROR: JSON file not found: $JsonPath"; exit 122 }
    $stateFromJson = Read-Json -Path $JsonPath
    if (-not $stateFromJson) { Write-FrontEndLog "ERROR: Parser returned null"; exit 122}
    Write-FrontEndLog "Data Loaded (tiny parser)"
} catch { Write-FrontEndLog ("ERROR: Unable to read/parse JSON: " + $_.Exception.Message); exit 122}
# Get only fields needed by the UI
$Product = $stateFromJson.Product
$Message = $stateFromJson.Message
$Timer   = if ($stateFromJson.Timer) { [int]$stateFromJson.Timer } else { 600 }
# Build $NormalizedProcessess with decoded icons
$NormalizedProcessess = @()
foreach ($item in $stateFromJson.Items) {
    $iconObj = $null
    if ($item.IconBase64) {
        try {
            $bytes = [Convert]::FromBase64String($item.IconBase64)
            $ms = New-Object IO.MemoryStream(,$bytes)
            $bmp = [System.Drawing.Image]::FromStream($ms)
            $iconObj = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
        } catch { $iconObj = [System.Drawing.SystemIcons]::Application }
    } else {
        $iconObj = [System.Drawing.SystemIcons]::Application
    }
    $NormalizedProcessess += ,@{ Name=$item.Name; Description=$item.Description; Icon=$iconObj }
}
Write-FrontEndLog "NormalizedProcessess built, count=$($NormalizedProcessess.Count)"
foreach ($proc in $NormalizedProcessess) { Write-FrontEndLog ("  Item: Name={0}, Desc={1}" -f $proc.Name,$proc.Description) }
if ($NormalizedProcessess.Count -eq 0) { Write-FrontEndLog "ERROR: No process extracted from JSON"; exit 122 }


# ----- Small helpers -----
function New-FontObject([string]$Family,[float]$Size,[System.Drawing.FontStyle]$Style) { New-Object System.Drawing.Font($Family,$Size,$Style,[System.Drawing.GraphicsUnit]::Point) }
function Set-ControlRoundRegion($Control,[int]$Radius) {
    if (-not $Control -or $Control.IsDisposed) { return }
    if ($Control.Width -le 0 -or $Control.Height -le 0) { return }
    try { $h = [Win32Native]::CreateRoundRectRgn(0,0,$Control.Width,$Control.Height,$Radius,$Radius); [Win32Native]::SetWindowRgn($Control.Handle,$h,$true) | Out-Null } catch {}
}
function Format-TimeString([int]$TotalSeconds,[Hashtable]$Loc) {
    if ($TotalSeconds -lt 0) { $TotalSeconds = 0 }
    $h = [int]([math]::Floor($TotalSeconds/3600)); $m = [int]([math]::Floor(($TotalSeconds%3600)/60)); $s = [int]($TotalSeconds%60)
    if ($h -gt 0) { return ("{0}{3} {1}{4} {2}{5}" -f $h,$m,$s,$Loc.HourSuffix,$Loc.MinSuffix,$Loc.SecSuffix) }
    elseif ($m -gt 0) { return ("{0}{2} {1}{3}" -f $m,$s,$Loc.MinSuffix,$Loc.SecSuffix) }
    else { return ("{0}{1}" -f $s,$Loc.SecSuffix) }
}

# ----- Colors, fonts, spacing -----
$ColorBlack          = [System.Drawing.Color]::FromArgb(0,0,0)
$ColorBlue1          = [System.Drawing.Color]::FromArgb(25,110,160)
$ColorBlue2          = [System.Drawing.Color]::FromArgb(40, 150, 230)
$ColorMainBackground = [System.Drawing.Color]::FromArgb(235,240,255)
$ColorCardBorder     = [System.Drawing.Color]::FromArgb(210,215,220)
$ColorTextMain       = [System.Drawing.Color]::FromArgb(45,45,60)
$ColorRed            = [System.Drawing.Color]::FromArgb(180,0,0)

$FontBase            = New-FontObject "Arial"    10 ([System.Drawing.FontStyle]::Regular)
$FontHeader          = New-FontObject "Arial"    18 ([System.Drawing.FontStyle]::Bold)
$FontText            = New-FontObject "Arial"    11 ([System.Drawing.FontStyle]::Regular)
$FontTextBold        = New-FontObject "Arial"    12 ([System.Drawing.FontStyle]::Bold)
$FontTextBoldUI      = New-FontObject "Segoe UI" 11 ([System.Drawing.FontStyle]::Bold)
$FontSmall           = New-FontObject "Arial"    9  ([System.Drawing.FontStyle]::Regular)

$cardHeight               = 48

# ----- Root form -----
$MainForm = New-Object System.Windows.Forms.Form
$MainForm.SuspendLayout()
$MainForm.AutoScaleDimensions = New-Object System.Drawing.SizeF(96,96)
$MainForm.AutoScaleMode = 'Dpi'
$MainForm.StartPosition = 'Manual'
$MainForm.FormBorderStyle = 'None'
$MainForm.ShowInTaskbar = $false
$MainForm.TopMost = $true
$MainForm.BackColor = $ColorMainBackground
$MainForm.Font = $FontBase
$MainForm.ClientSize = New-Object System.Drawing.Size(600,294)
$MainForm.MaximumSize = New-Object System.Drawing.Size(600, (294 + $cardHeight*3))

# Layout root (sidebar + main area)
$RootLayout = New-Object System.Windows.Forms.TableLayoutPanel
$RootLayout.Dock = 'Fill'; $RootLayout.ColumnCount=2; $RootLayout.RowCount=1
$SbW = if ($SidebarLogoBase64) {12} else {4}
$null = $RootLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent,$SbW))) # Left SideBar
$null = $RootLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent,88)))   # Main column
$null = $RootLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent,100)))        # Main row

$SidebarPanel = New-Object System.Windows.Forms.Panel
$SidebarPanel.Dock = 'Fill' ; $SidebarPanel.BackColor = $ColorBlue1
$SidebarPanel.Margin = [System.Windows.Forms.Padding]::Empty        ; $SidebarPanel.Padding = New-Object System.Windows.Forms.Padding(10,0,10,0)
$SidebarPanel.add_MouseEnter({ $SidebarPanel.BackColor = $ColorBlue2; $SidebarPanel.Cursor = [System.Windows.Forms.Cursors]::SizeAll })
$SidebarPanel.add_MouseLeave({ $SidebarPanel.BackColor = $ColorBlue1 ; $SidebarPanel.Cursor = [System.Windows.Forms.Cursors]::Default })

$MainPanel = New-Object System.Windows.Forms.Panel
$MainPanel.Dock='Fill'; $MainPanel.BackColor=$ColorMainBackground
$MainPanel.Padding=New-Object System.Windows.Forms.Padding(12,0,12,0)

$RootLayout.Controls.Add($SidebarPanel,0,0)
$RootLayout.Controls.Add($MainPanel,1,0)

# Main content layout
$MainContent = New-Object System.Windows.Forms.TableLayoutPanel
$MainContent.Dock='Fill'; $MainContent.ColumnCount=1; $MainContent.RowCount=5
$null = $MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,63))) # Title
$null = $MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent,100))) # Central zone
$null = $MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,17))) # Spacer
$null = $MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,28))) # Button zone
$null = $MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,17))) # Spacer
$MainPanel.Controls.Add($MainContent)

# Header label
$HeaderLabel = New-Object System.Windows.Forms.Label
$HeaderLabel.Text = $Locale.InstallingOf + $Product
$HeaderLabel.ForeColor = $ColorTextMain
$HeaderLabel.Font = $FontHeader
$HeaderLabel.AutoSize = $false
$HeaderLabel.Dock = 'Fill'
$HeaderLabel.TextAlign = 'MiddleLeft'

# Card with message + process list + status bar
$CardBorderPanel = New-Object System.Windows.Forms.Panel
$CardBorderPanel.Dock='Fill'; $CardBorderPanel.BackColor=$ColorCardBorder; $CardBorderPanel.Padding=New-Object System.Windows.Forms.Padding(1)
$CardPanel = New-Object System.Windows.Forms.Panel
$CardPanel.Dock='Fill'; $CardPanel.BackColor=[System.Drawing.Color]::White; $CardPanel.Padding=New-Object System.Windows.Forms.Padding(16)
$CardBorderPanel.Controls.Add($CardPanel)

$CardLayout = New-Object System.Windows.Forms.TableLayoutPanel
$CardLayout.Dock='Fill'; $CardLayout.ColumnCount=1; $CardLayout.RowCount=3
$null = $CardLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))    # Message
$null = $CardLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent,100))) # Processes zone
$null = $CardLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))    # Countdown zone
$CardPanel.Controls.Add($CardLayout)

# Info message (auto-wrap by MaximumSize)
$InfoLabel = New-Object System.Windows.Forms.Label
$InfoLabel.AutoSize=$true; $InfoLabel.Font=$FontText; $InfoLabel.ForeColor=$ColorTextMain
$InfoLabel.Text = if ([string]::IsNullOrEmpty($Message)) { $Locale.DefaultInfo } else { $Message }
$InfoLabel.Dock='Top'; $InfoLabel.Margin=New-Object System.Windows.Forms.Padding(0,0,0,8)
$CardLayout.Controls.Add($InfoLabel,0,0)
$AdjustInfoWidth = { $p=$InfoLabel.Parent; if ($p -and -not $p.IsDisposed) { $w=[Math]::Max(100,$p.ClientSize.Width - $InfoLabel.Margin.Left - $InfoLabel.Margin.Right); $InfoLabel.MaximumSize=New-Object System.Drawing.Size($w,0) } }
& $AdjustInfoWidth
$null = $MainForm.add_Shown($AdjustInfoWidth)

# Process zone with border + scroll
$ProcessBorderPanel = New-Object System.Windows.Forms.Panel
$ProcessBorderPanel.Dock='Fill'; $ProcessBorderPanel.BackColor=$ColorCardBorder; $ProcessBorderPanel.Padding=New-Object System.Windows.Forms.Padding(1)
$ProcessScrollPanel = New-Object System.Windows.Forms.Panel
$ProcessScrollPanel.Dock='Fill'; $ProcessScrollPanel.BackColor=[System.Drawing.Color]::White; $ProcessScrollPanel.Padding=New-Object System.Windows.Forms.Padding(10); $ProcessScrollPanel.AutoScroll=$true
$ProcessBorderPanel.Controls.Add($ProcessScrollPanel)
$CardLayout.Controls.Add($ProcessBorderPanel,0,1)

$ProcessFlow = New-Object System.Windows.Forms.FlowLayoutPanel
$ProcessFlow.Dock='Fill'; $ProcessFlow.WrapContents=$false; $ProcessFlow.FlowDirection='TopDown'; $ProcessFlow.AutoScroll=$true; $ProcessFlow.Padding=New-Object System.Windows.Forms.Padding(0)
$ProcessScrollPanel.Controls.Add($ProcessFlow)

# Status bar (pulse | label | timer)
$StatusBar = New-Object System.Windows.Forms.TableLayoutPanel
$StatusBar.Dock='Fill'; $StatusBar.Height=28; $StatusBar.BackColor=[System.Drawing.Color]::White
$StatusBar.Padding=New-Object System.Windows.Forms.Padding(10,0,10,0); $StatusBar.Margin=New-Object System.Windows.Forms.Padding(0,20,0,0)
$StatusBar.RowCount=1; $StatusBar.ColumnCount=3
$null = $StatusBar.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))    # Pulse animation
$null = $StatusBar.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent,100))) # Countdown label
$null = $StatusBar.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))    # Countdown timer
$null = $StatusBar.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent,100)))
$CardLayout.Controls.Add($StatusBar,0,2)

$PulsePictureBox = New-Object Windows.Forms.PictureBox -Property @{ Width=20; Height=20; SizeMode='CenterImage'; Anchor='None' }
$StatusBar.Controls.Add($PulsePictureBox,0,0)
$CountdownTextLabel = New-Object Windows.Forms.Label -Property @{ AutoSize=$true; Font=$FontText; Text=$Locale.CountdownLabel; ForeColor=$ColorTextMain; TextAlign='MiddleLeft'; Dock='Left'; Margin=(New-Object Windows.Forms.Padding(6,0,0,0)) }
$StatusBar.Controls.Add($CountdownTextLabel,1,0)
$CountdownValueLabel = New-Object Windows.Forms.Label -Property @{ AutoSize=$true; Font=$FontTextBold; Text=(Format-TimeString $Timer $Locale); ForeColor=$ColorTextMain; TextAlign='MiddleRight'; Dock='Right'; Margin=(New-Object Windows.Forms.Padding(0,0,0,3)) }
$StatusBar.Controls.Add($CountdownValueLabel,2,0)

# Pulse animation
function New-PulseFrameBitmap($Size,$Scale,$Alpha,$BaseColor=$null) {
    if (-not $BaseColor) { $BaseColor = $ColorBlue1 } # default: bleu
    $bmp = New-Object Drawing.Bitmap $Size,$Size
    $gfx = [Drawing.Graphics]::FromImage($bmp); $gfx.SmoothingMode='AntiAlias'
    $color = [Drawing.Color]::FromArgb([math]::Min([math]::Max([int]$Alpha,0),255),$BaseColor.R,$BaseColor.G,$BaseColor.B)
    $radius = ($Size/1.2)*$Scale
    $rect = New-Object Drawing.RectangleF((($Size/2)-$radius-0.6),(($Size/2)-$radius-0.6),(2*$radius),(2*$radius))
    $gfx.FillEllipse((New-Object Drawing.SolidBrush $color),$rect)
    $gfx.Dispose()
    return $bmp
}
$PulseAnim = @{ Size=15; Phase=0.0; Interval=30; Speed=0.05 }
$PulsePictureBox.Image = New-PulseFrameBitmap $PulseAnim.Size 0.9 200
$PulseTimer = New-Object Windows.Forms.Timer -Property @{ Interval=$PulseAnim.Interval }
$PulseTimer.add_Tick({
    $PulseAnim.Phase += $PulseAnim.Speed
    $sine = [math]::Sin($PulseAnim.Phase)/2.0
    $scale = 0.75 + $sine
    $alpha = 120 + ($sine*150)
    $baseColor = $ColorBlue1
    if ($MainForm -and $MainForm.Tag -and $MainForm.Tag.ContainsKey('Remaining')) {if ($MainForm.Tag['Remaining'] -lt 60) { $baseColor = $ColorRed }}
    $oldImg,$PulsePictureBox.Image = $PulsePictureBox.Image,(New-PulseFrameBitmap $PulseAnim.Size $scale $alpha $baseColor)
    if ($oldImg) { $oldImg.Dispose() }
})
$MainForm.add_Shown({ $PulseTimer.Start() })
$MainForm.add_FormClosed({ $PulseTimer.Stop(); if($PulsePictureBox.Image){$PulsePictureBox.Image.Dispose()} })

$CloseButton = New-Object NoFocusButton
$CloseButton.Text=$Locale.ActionButton; $CloseButton.Font=$FontTextBold; $CloseButton.Width=285
$CloseButton.Dock='Right'; $CloseButton.Margin=New-Object System.Windows.Forms.Padding(0,0,5,0)
$CloseButton.FlatStyle='Flat'
$CloseButton.FlatAppearance.MouseOverBackColor=$ColorBlue2
$CloseButton.FlatAppearance.MouseDownBackColor=$ColorBlack
$CloseButton.FlatAppearance.BorderSize=0
$CloseButton.BackColor=$ColorBlue1
$CloseButton.ForeColor=[System.Drawing.Color]::White
$CloseButton.add_MouseUp({ $MainForm.ActiveControl = $null })
$CloseButton.add_Click({ $MainForm.Close() })
$CloseButton.TabStop = $false

# Compose main layout sections
$MainContent.Controls.Add($HeaderLabel,0,0)
$MainContent.Controls.Add($CardBorderPanel,0,1)
$MainContent.Controls.Add($CloseButton,0,3)
$MainForm.Controls.Add($RootLayout)

# ----- Per-process item builder -----
function New-ProcessRowPanel($Icon,[string]$DisplayDescription,[string]$ExecutableName) {
    $row = New-Object System.Windows.Forms.TableLayoutPanel
    $row.Width=if ($SidebarLogoBase64) {410} else {460}; $row.Height=$cardHeight; $row.Margin = New-Object System.Windows.Forms.Padding 0,0,0,0
    $row.BackColor=[System.Drawing.Color]::White; $row.ColumnCount=2; $row.RowCount=1
    $null = $row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle ([System.Windows.Forms.SizeType]::Absolute,64))) # Process icon
    $null = $row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle ([System.Windows.Forms.SizeType]::Percent,100))) # Process infos
    $null = $row.RowStyles.Add((New-Object System.Windows.Forms.RowStyle ([System.Windows.Forms.SizeType]::Percent,100))) 

    $iconBox = New-Object System.Windows.Forms.PictureBox
    $iconBox.SizeMode='CenterImage'; $iconBox.Image=$Icon.ToBitmap(); $iconBox.Dock='Fill'

    $textStack = New-Object System.Windows.Forms.TableLayoutPanel
    $textStack.Dock='Fill'; $textStack.ColumnCount=1; $textStack.RowCount=2
    $null = $textStack.RowStyles.Add((New-Object System.Windows.Forms.RowStyle ([System.Windows.Forms.SizeType]::Percent,50))) # Process description
    $null = $textStack.RowStyles.Add((New-Object System.Windows.Forms.RowStyle ([System.Windows.Forms.SizeType]::Percent,50))) # Process name

    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = if ([string]::IsNullOrEmpty($DisplayDescription)) { $ExecutableName } else { $DisplayDescription }
    $titleLabel.Dock='Fill'; $titleLabel.TextAlign='MiddleLeft'; $titleLabel.Font=$FontTextBoldUI
    $titleLabel.ForeColor=$ColorTextMain; $titleLabel.AutoSize=$false; $titleLabel.AutoEllipsis=$true

    $exeLabel = New-Object System.Windows.Forms.Label
    $exeLabel.Text=$ExecutableName; $exeLabel.Dock='Fill'; $exeLabel.TextAlign='MiddleLeft'
    $exeLabel.Font=$FontSmall; $exeLabel.ForeColor=$ColorBlue1

    $null = $textStack.Controls.Add($titleLabel,0,0)
    $null = $textStack.Controls.Add($exeLabel,0,1)
    $null = $row.Controls.Add($iconBox,0,0)
    $null = $row.Controls.Add($textStack,1,0)
    return $row
}

Write-FrontEndLog "Building UI rows for $($NormalizedProcessess.Count) processes..."

foreach ($proc in $NormalizedProcessess) {
    $MainForm.Height += $cardHeight
    $itemPanel = New-ProcessRowPanel -Icon $proc.Icon -DisplayDescription $proc.Description -ExecutableName $proc.Name
    $ProcessFlow.Controls.Add($itemPanel) | Out-Null
}

try {
    [byte[]]$b = [Convert]::FromBase64String($SidebarLogoBase64)
    $ms = New-Object System.IO.MemoryStream($b,$false)
    $img = [System.Drawing.Image]::FromStream($ms,$true,$true)
    $bmp = New-Object System.Drawing.Bitmap($img)
    $img.Dispose(); $ms.Dispose()
    $bmp.RotateFlip([System.Drawing.RotateFlipType]::Rotate270FlipNone)
    $logoBox = New-Object TransparentPictureBox
    $logoBox.Dock='Fill'; $logoBox.SizeMode='Zoom'; $logoBox.BackColor=[System.Drawing.Color]::Transparent; $logoBox.Image=$bmp
    [void]$SidebarPanel.Controls.Add($logoBox)
    $MainForm.add_FormClosed({ try { if ($logoBox.Image) { $logoBox.Image.Dispose() } } catch {} })
} catch {}

# ----- Initial placement (bottom-right of primary working area) -----
$MainForm.ResumeLayout()
$work = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$MainForm.Location = New-Object System.Drawing.Point([Math]::Max(0,$work.Right-$MainForm.Width),[Math]::Max(0,$work.Bottom-$MainForm.Height))

# ----- Rounded corners + resize maintenance -----
$MainForm.add_Shown({ Set-ControlRoundRegion $MainForm 20; Set-ControlRoundRegion $CardBorderPanel 12; Set-ControlRoundRegion $CardPanel 10; Set-ControlRoundRegion $ProcessBorderPanel 9; Set-ControlRoundRegion $ProcessScrollPanel 7 })
$MainForm.add_Resize({ Set-ControlRoundRegion $MainForm 20; Set-ControlRoundRegion $CardBorderPanel 12; Set-ControlRoundRegion $CardPanel 10; Set-ControlRoundRegion $ProcessBorderPanel 9; Set-ControlRoundRegion $ProcessScrollPanel 7 })

# ----- Countdown timer (UI update + close at zero) -----
$MainForm.Tag = @{ Remaining=[Math]::Max(0,$Timer); CountdownTimer=(New-Object System.Windows.Forms.Timer) }
$MainForm.Tag.CountdownTimer.Interval = 1000
$MainForm.Tag.CountdownTimer.add_Tick({
    $MainForm.Tag['Remaining'] = $MainForm.Tag['Remaining'] - 1
    $CountdownValueLabel.Text = Format-TimeString -TotalSeconds $MainForm.Tag['Remaining'] -Loc $Locale
    if ($MainForm.Tag['Remaining'] -lt 60) { $CountdownValueLabel.ForeColor = $ColorRed } else { $CountdownValueLabel.ForeColor = $ColorTextMain }
    if ($MainForm.Tag['Remaining'] -le 0) { $MainForm.Tag.CountdownTimer.Stop(); $MainForm.Close() }
})
$MainForm.add_Shown({ $MainForm.Tag.CountdownTimer.Start() ; Write-FrontEndLog "Form Shown." })

# ----- Drag anywhere on sidebar or header, like a title bar -----
function Enable-WindowDragOnControl($Control) {
    $Control.add_MouseDown({
        if ($_.Button -eq [Windows.Forms.MouseButtons]::Left) {
            [Win32Native]::ReleaseCapture() | Out-Null
            [Win32Native]::SendMessage($MainForm.Handle,0xA1,0x2,0) | Out-Null
        }
    })
    foreach ($child in $Control.Controls) { Enable-WindowDragOnControl $child }
}
Enable-WindowDragOnControl $SidebarPanel
Enable-WindowDragOnControl $MainContent.GetControlFromPosition(0,0)

# ----- Clamp to primary screen when drag ends, or when moved across screens -----
$MessageHook = New-Object Win32MsgHelper $MainForm
$MessageHook.add_DragFinished({
    $primary = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $b = $MainForm.Bounds
    $x = [Math]::Max($primary.Left,[Math]::Min($b.Left,$primary.Right-$b.Width))
    $y = [Math]::Max($primary.Top,[Math]::Min($b.Top,$primary.Bottom-$b.Height))
    if ($x -ne $b.Left -or $y -ne $b.Top -or [System.Windows.Forms.Screen]::FromControl($MainForm) -ne [System.Windows.Forms.Screen]::PrimaryScreen) {
        $MainForm.Location = New-Object Drawing.Point $x,$y
    }
})

# ----- Show modal loop -----
[void][System.Windows.Forms.Application]::Run($MainForm)
'@
    ###############################  End of FrontEnd Script  ###############################

    try {
        $encoding = New-Object System.Text.UTF8Encoding $true  # $true = BOM
        [System.IO.File]::WriteAllText($FrontEndpath,$frontContent,$encoding)
        Write-CustomLog ("FrontEnd script written: " + $FrontEndpath + " (length=" + $frontContent.Length + ")")
    } catch {
        Write-CustomLog ("ERROR: failed to write FrontEnd script in '$FrontEndpath':" + $_.Exception.Message)
        Stop-Script 3
    }
    $payload = Merge-JsonPayload -Product $Product -Message $Message -Timer $Timer -DetectedProcesses $DetectedProcesses -WorkDir $WorkDir -Log $script:LogPath -Attempts $Attempts -Test:$Test.IsPresent
    $JsonPath = Write-Json -WorkDir $WorkDir -Product $Product -Payload $payload
}

# ---------- UI strategy (shared for fresh run or JSON-restore) ----------
$pwsh = Resolve-PwshExe
$FrontEndExitCode = $null
$launchOk         = $false
$principalInfo = Get-SessionContext
$FrontEndArgsLine = @(
    '-NoLogo','-NoProfile','-Ex','Bypass',
    '-File',(Format-CommandLineArgument $FrontEndPath),
    '-JsonPath',(Format-CommandLineArgument $JsonPath),
    '-log',(Format-CommandLineArgument $script:LogPath)
) -join ' '
Write-CustomLog "FrontEndArgsLine=$FrontEndArgsLine"

if ($principalInfo.IsSystem) {
    # === Scenario 1: Running as system -> Create powershell process as user to show UI ===
    $targetSessionId = $null
    # Determine the target interactive session (RDP or Console)
    if ($principalInfo.HasActiveUserSession -and $null -ne $principalInfo.ActiveUserSessionId) {
        $targetSessionId = [int]$principalInfo.ActiveUserSessionId
    } else {
        $consoleSessionId = [WtsApi32]::WTSGetActiveConsoleSessionId()
        if ($consoleSessionId -ge 0) { $targetSessionId = $consoleSessionId }
    }
    if ($null -eq $targetSessionId -or $targetSessionId -lt 0) {
        Write-CustomLog "No interactive session found (RDP/Console). Exiting with 22."
        Stop-Script 22
    }
    # Token retrieval/duplication, process creation and waiting
    $launchResult = Start-FromSystemAsCurrentUser -SessionId $targetSessionId -ExePath $pwsh -ArgumentsLine $frontEndArgsLine -ShowWindow:$Test
    $launchOk = [bool]($launchResult -and $launchResult.Success)
    if ($launchResult -and $launchResult.ContainsKey('ExitCode') -and $null -ne $launchResult.ExitCode) {$FrontEndExitCode = [int]$launchResult.ExitCode}
    if ($launchOk) {
        if ($null -eq $FrontEndExitCode) {Write-CustomLog "ERROR:FrontEnd launched, but exit code not available"; Stop-Script 12}
        elseif ($FrontEndExitCode -eq 0) {Write-CustomLog "FrontEnd Completed"}
        else                             {Write-CustomLog "ERROR: FrontEnd returned exit code '$FrontEndExitCode'"; Stop-Script 12}
    } else                               {Write-CustomLog "ERROR: FrontEnd not launched"; Stop-Script 12}
}
elseif ($principalInfo.IsProcessInteractive) {
    # === Scenario 2: interactive user -> launch directly and wait ===
    $launchResult = Start-FromCurrentUser -Pwsh $pwsh -ArgumentsLine $FrontEndArgsLine -ShowWindow:$Test
    $launchOk = [bool]($launchResult -and $launchResult.Success)
    if ($launchResult -and $launchResult.ContainsKey('ExitCode') -and $null -ne $launchResult.ExitCode) {$FrontEndExitCode = [int]$launchResult.ExitCode}
    Write-CustomLog ("Start-FromCurrentUser returned: Success=" + $launchOk + ", ExitCode=" + ($FrontEndExitCode -as [string]))
    if ($launchOk) {
        if ($null -eq $FrontEndExitCode) {Write-CustomLog "ERROR:FrontEnd launched, but exit code not available"; Stop-Script 12}
        elseif ($FrontEndExitCode -eq 0) {Write-CustomLog "FrontEnd Completed"}
        else                             {Write-CustomLog "ERROR: FrontEnd returned exit code '$FrontEndExitCode'"; Stop-Script 12}
    } else                               {Write-CustomLog "ERROR: FrontEnd not launched"; Stop-Script 12}
}
elseif ($principalInfo.HasActiveUserSession) {
    # === Scenario 3: non-interactive & not SYSTEM, but an active user session exists -> relaunch via SYSTEM task passing only $JsonPath ===
    Write-CustomLog "Non-interactive and not SYSTEM, with an active user session -> relaunching self via SYSTEM scheduled task."
    if (-not $MyInvocation.MyCommand.Path) {
        Write-CustomLog "ERROR: MyInvocation.MyCommand.Path returned nothing (scenario 3)"
        Stop-Script 9
    }
    if (-not (Test-Path -LiteralPath $MyInvocation.MyCommand.Path)) {
        Write-CustomLog ("ERROR: cannot resolve current script path '$($MyInvocation.MyCommand.Path)'")
        Stop-Script 9 
    }
    $systemTaskResult = Invoke-ViaSystemScheduledTaskAndWait -ScriptPath $MyInvocation.MyCommand.Path -JsonPath $JsonPath -TimeoutSeconds $Timer
    if (-not $systemTaskResult -or -not $systemTaskResult.ContainsKey('ExitCode') -or $null -eq $systemTaskResult.ExitCode) {
        Write-CustomLog "WARN: SYSTEM task returned without an exit code."
        Stop-Script 13
    } elseif ([int]$systemTaskResult.ExitCode -ne 0) {
        Write-CustomLog ("ERROR: SYSTEM task exit code: " + [int]$systemTaskResult.ExitCode)
        Stop-Script 13
    }
    $finalExit = if ($systemTaskResult -and $systemTaskResult.ContainsKey('ExitCode') -and $null -ne $systemTaskResult.ExitCode) { [int]$systemTaskResult.ExitCode } else { 6 }
    exit $finalExit
}


# ==================================================================
#                           CLOSE PROCESSES
# ==================================================================

function Close-DetectedProcesses($DetectedProcesses, [int]$Attempts = 8) {
    if (-not $DetectedProcesses) { Write-CustomLog "Skip close: no detected items"; return }
    if ($Attempts -lt 1) { $Attempts = 1 }
    $ProcessNames=@(); foreach($d in $DetectedProcesses){ if($d.Name){ $ProcessNames += $d.Name.Trim() } }
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
    if ($survivors.Count -gt 0) { Write-CustomLog ("ERROR: still running after " + $Attempts + " attempts: " + ($survivors -join ", ")); Stop-Script 8 }
    else { Write-CustomLog ("All targeted process names are no longer running after " + $Attempts + " attempts") }
}

# Only close if: launch OK + FrontEnd ExitCode 0 + not Test
if (-not $Test) {
    Write-CustomLog "Front-end reported success and no -Test flag set -> closing detected processes..."
    Close-DetectedProcesses -DetectedProcesses $DetectedProcesses -Attempts $Attempts
} else { Write-CustomLog "Test mode -> not closing processes." }

Stop-Script 0
