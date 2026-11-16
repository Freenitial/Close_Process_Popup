<# ::
    @echo off & setlocal
    set "CPPversion=1.4"
    title Close Processes Popup v%CPPversion% Launcher

    for %%A in ("" "/?" "-?" "--?" "/help" "-help" "--help") do if /I "%~1"=="%%~A" goto :help
    
    if exist %SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe   set "powershell=%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe"
    if exist %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe  set "powershell=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"

    set args=%*
    if defined args set args=%args:^=^^%
    if defined args set args=%args:<=^<%
    if defined args set args=%args:>=^>%
    if defined args set args=%args:&=^&%
    if defined args set args=%args:|=^|%
    if defined args set "args=%args:"=\"%"
    
    :: PowerShell self-read, skipping batch part
    "%powershell%" -NoLogo -NoProfile -Ex Bypass -Command ^
        "$sb=[ScriptBlock]::Create([IO.File]::ReadAllText('%~f0'));& $sb @args" %args%

    exit /b %errorlevel% 

    :help
    cls
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
    echo       -ProcessTitle (string list)
    echo          Close PID by window title. Can filter by process when adding "="
    echo          Before "=" : Window title (Wildcard * compatible)
    echo          After  "=" : Filter by process
    echo          Example: -ProcessTitle *paint,Message*=CSRSS.exe
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
    echo       schtasks /create /tn "SysPWSh" /tr "cmd /c \"\"C:\Path\CloseProcessPopup.bat\" -Process \"chrome=Google Chrome\" -PopupTitle \"ADOBE\" -test\"" /sc onstart /ru SYSTEM ^& schtasks /run /tn "SysPWSh" ^& schtasks /delete /tn "SysPWSh" /f
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
    echo    16  = Critical system process detected, cannot proceed
    echo    17  = Failed to enumerate running processes
    echo.
    echo    =============================================================================
    echo.
    echo Press any key to exit.
    echo.
    pause >nul & exit /b
#>

#requires -version 2.0
<#
.SYNOPSIS
    Warns the logged-on users that applications are about to be closed, then terminates the matching processes.
.DESCRIPTION
    Processes are selected by executable name (-Process), executable path (-ProcessPath), loaded module (-ProcessDLL) or window title (-ProcessTitle).
    When -PopupTitle is provided, a countdown popup is displayed in every active user session concerned by the request.
    Processes are terminated through handles opened at detection time, then every pass re-scans the system until nothing matches anymore.

    Exit codes :
       0 : every targeted process is closed (or -Test was used)
       2 : none of the requested processes is running
       6 : the Windows sessions could not be enumerated
      10 : the script was not started with Administrator or SYSTEM rights
      11 : no -Process, -ProcessPath, -ProcessTitle or -ProcessDLL argument was provided
      13 : a popup is required but the script runs neither as SYSTEM nor inside an interactive session
      15 : some targeted processes are still running after the last pass
      16 : a wildcard, path or DLL pattern matched a critical system process
      17 : the running processes could not be enumerated
      30 : the popup could not be displayed in a user session, nothing was closed
#>
Param(
    [Parameter(Mandatory=$false)][Alias('ProductName','Product')]                     [string]$PopupTitle,     # -PopupTitle  "Adobe Acrobat" (NO POPUP IF MISSING)
    [Parameter(Mandatory=$false)][Alias('Processes','CloseProcess','CloseProcesses')] [string[]]$Process,      # -Process     "chrome=Google Chrome","acrobat.exe=Adobe Acrobat","acro*"
    [Parameter(Mandatory=$false)][Alias('Path','Paths')]                              [string[]]$ProcessPath,  # -ProcessPath "C:\Program Files\Google","C:\Program Files\Adobe\*\Acro*.exe" (a path without wildcard is a folder searched recursively, or a single .exe)
    [Parameter(Mandatory=$false)][Alias('Title','Titles','ProcessTitles')]            [string[]]$ProcessTitle, # -ProcessTitle "*paint","Report*=excel.exe"
    [Parameter(Mandatory=$false)][Alias('DLL','DLLpattern','UnlockDLL')]              [string[]]$ProcessDLL,   # -ProcessDLL  acroRd32.dll,"C:\Program Files\Adobe\*.dll"
    [Parameter(Mandatory=$false)][Alias('CountDown')]                                 [int]$Timer=600,         # -Timer 600   (in seconds)
    [Parameter(Mandatory=$false)][Alias('Retry')]                                     [int]$Attempts=8,        # -Attempts 8  (maximum number of scan + terminate passes)
    [Parameter(Mandatory=$false)][Alias('NoKill','ShowConsole')]                      [switch]$Test,           # -Test        (do not close processes at the end, show the child consoles)
    [Parameter(Mandatory=$false)][Alias('LogFile','LogName','LogPath')]               [string]$Log             # -Log MyLog.log  OR  -Log C:\MyPath\MyLog.log
)
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR : Need Admin or System rights at launch"
    exit 10
}
if (-not ($Process -or $ProcessPath -or $ProcessTitle -or $ProcessDLL)) {
    $usageWarning = "`nERROR : Incorrect arguments provided. Required arguments :`n`n" +
                    "   -PopupTitle xxx  (if you want to show popup, otherwise no popup)`n" +
                    "       AND`n" +
                    "   -Process xxx   OR   -ProcessPath xxx   OR   -ProcessDLL xxx   OR   -ProcessTitle xxx`n"
    Write-Host $usageWarning
    Write-Host "Arguments provided :`nPopupTitle= $PopupTitle`nProcess= $Process`nProcessPath= $ProcessPath`nProcessDLL= $ProcessDLL`nProcessTitle= $ProcessTitle"
    exit 11
}


# ==================================================================
#                      ARCHITECTURE BOOTSTRAP
# ==================================================================

function Format-SingleQuotedLiteral([string]$RawText) {
    # Returns a PowerShell single-quoted literal. The parser accepts the typographic quotes U+2018 to U+201B as string delimiters,
    # so each of them is doubled exactly like the ASCII apostrophe
    return "'" + ($RawText -replace "(['\u2018\u2019\u201A\u201B])",'$1$1') + "'"
}

function Get-ArchitectureContext {
    # PROCESSOR_ARCHITECTURE describes the current process (AMD64 inside a 64-bit process, x86 inside a 32-bit one),
    # PROCESSOR_ARCHITEW6432 only exists inside a 32-bit process hosted by a 64-bit OS
    # Either variable can be missing when the caller provides a custom environment block, so the pointer size
    # and the Sysnative alias (only visible from a 32-bit process on a 64-bit OS) are used as additional evidence
    $processArchitecture = [string]$env:PROCESSOR_ARCHITECTURE
    $wow64Architecture = [string]$env:PROCESSOR_ARCHITEW6432
    $sysnativePowerShellPath = Join-Path $script:WindowsDirectory "Sysnative\WindowsPowerShell\v1.0\powershell.exe"
    $isSysnativeVisible = [bool](Test-Path -LiteralPath $sysnativePowerShellPath)
    $isProcess64Bit = ([IntPtr]::Size -eq 8)
    $isOperatingSystem64Bit = $isProcess64Bit -or ($processArchitecture -eq 'AMD64') -or ($processArchitecture -eq 'ARM64') -or ($processArchitecture -eq 'IA64') -or (-not [string]::IsNullOrEmpty($wow64Architecture)) -or $isSysnativeVisible
    return @{
        ProcessArchitecture     = $processArchitecture
        Wow64Architecture       = $wow64Architecture
        IsProcess64Bit          = $isProcess64Bit
        IsOperatingSystem64Bit  = $isOperatingSystem64Bit
        IsSysnativeVisible      = $isSysnativeVisible
        SysnativePowerShellPath = $sysnativePowerShellPath
    }
}

function Invoke-NativeArchitectureRelaunch {
    # A 32-bit process cannot enumerate the modules of 64-bit processes, so on a 64-bit OS the whole script runs in the native host
    # The command is rebuilt from the bound parameters and passed as -EncodedCommand, which preserves arrays and avoids every quoting issue
    param([hashtable]$ArchitectureContext, [System.Collections.IDictionary]$BoundParameters, [string]$ScriptPath)
    if ($ArchitectureContext.IsProcess64Bit -or -not $ArchitectureContext.IsOperatingSystem64Bit) { return }
    if ([string]::IsNullOrEmpty($ScriptPath) -or -not $ArchitectureContext.IsSysnativeVisible) {
        Write-Host "WARNING : 32-bit process on a 64-bit OS and no way to relaunch in 64-bit, -ProcessDLL will not see the modules of 64-bit processes"
        return
    }
    Write-Host ("32-bit process on a 64-bit OS (PROCESSOR_ARCHITECTURE=" + $ArchitectureContext.ProcessArchitecture + ", PROCESSOR_ARCHITEW6432=" + $ArchitectureContext.Wow64Architecture + ") : relaunching in the native 64-bit PowerShell host")
    $commandBuilder = New-Object Text.StringBuilder
    [void]$commandBuilder.Append("& " + (Format-SingleQuotedLiteral $ScriptPath))
    foreach ($parameterName in $BoundParameters.Keys) {
        $parameterValue = $BoundParameters[$parameterName]
        if ($parameterValue -is [System.Management.Automation.SwitchParameter]) {
            if ($parameterValue.IsPresent) { [void]$commandBuilder.Append(" -" + $parameterName) }
        } else {
            $quotedValues = @()
            foreach ($singleValue in @($parameterValue)) { $quotedValues += (Format-SingleQuotedLiteral ([string]$singleValue)) }
            [void]$commandBuilder.Append(" -" + $parameterName + " " + ($quotedValues -join ","))
        }
    }
    [void]$commandBuilder.Append('; exit $LASTEXITCODE')
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($commandBuilder.ToString()))
    $nativePowerShellPath = $ArchitectureContext.SysnativePowerShellPath
    # The exit code is only trusted when the native host really ran, a stale value would report a success that never happened
    $global:LASTEXITCODE = $null
    try { & $nativePowerShellPath -NoLogo -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand } catch { Write-Host ("WARNING : the native 64-bit host could not be started : " + $_.Exception.Message) }
    if ($null -eq $global:LASTEXITCODE) {
        Write-Host "WARNING : continuing inside the 32-bit process, -ProcessDLL will not see the modules of 64-bit processes"
        return
    }
    exit $global:LASTEXITCODE
}

$script:IsTestMode = [bool]$Test
$script:WindowsDirectory = Split-Path -Parent ([Environment]::SystemDirectory)
$script:ArchitectureContext = Get-ArchitectureContext
Invoke-NativeArchitectureRelaunch -ArchitectureContext $script:ArchitectureContext -BoundParameters $PSBoundParameters -ScriptPath $MyInvocation.MyCommand.Path
# Child PowerShell processes always use the native host : Sysnative is only reachable when the relaunch above was impossible
$script:PowerShellPath = Join-Path $script:WindowsDirectory "System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not $script:ArchitectureContext.IsProcess64Bit -and $script:ArchitectureContext.IsSysnativeVisible) { $script:PowerShellPath = $script:ArchitectureContext.SysnativePowerShellPath }


# ==================================================================
#                         NATIVE P/INVOKE
# ==================================================================

Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
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
    [DllImport("wtsapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool WTSEnumerateSessions(IntPtr hServer, int Reserved, int Version, out IntPtr ppSessionInfo, out int pCount);
    [DllImport("wtsapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool WTSQuerySessionInformation(IntPtr hServer, int sessionId, int wtsInfoClass, out IntPtr ppBuffer, out int pBytesReturned);
    [DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr pMemory);
}
[StructLayout(LayoutKind.Sequential)]
public struct WTS_SESSION_INFO { public int SessionId; public IntPtr pWinStationName; public int State; }
public class Win32Api {
    public const int HANDLE_FLAG_INHERIT=0x1;
    [StructLayout(LayoutKind.Sequential)] public struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle; }
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetHandleInformation(IntPtr hObject, int dwMask, int dwFlags);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool ProcessIdToSessionId(int dwProcessId, out int pSessionId);
    [DllImport("kernel32.dll", CharSet=CharSet.Auto, SetLastError=true)] public static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);
    [DllImport("psapi.dll", SetLastError=true)] public static extern bool EnumProcesses([MarshalAs(UnmanagedType.LPArray, ArraySubType=UnmanagedType.U4)] int[] processIds, int size, [MarshalAs(UnmanagedType.U4)] out int bytesReturned);
    [DllImport("psapi.dll", SetLastError=true)] public static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag);
    [DllImport("psapi.dll", CharSet=CharSet.Auto, SetLastError=true)] public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, uint nSize);
    [DllImport("userenv.dll", SetLastError=true)] public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
    [DllImport("userenv.dll", SetLastError=true)] public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
}
'@

# Process access rights used with OpenProcess
$script:ProcessAccess = @{ Terminate=0x0001; VmRead=0x0010; QueryInformation=0x0400; QueryLimitedInformation=0x1000; Synchronize=0x00100000 }
# Markers written by the popup on its output stream, they are the only popup feedback the backend trusts
$script:PopupSignalPrefix = "##CloseProcessPopup:"
$script:PopupSignalSuffix = "##"


# ==================================================================
#                            UTILITIES
# ==================================================================

function Stop-Script([int]$ExitCode) {
    try { Write-CustomLog "========================================="; Write-CustomLog "" -NoPrefix } catch {}
    try { if ($script:LogMutex) { $script:LogMutex.Close() } } catch {}
    exit $ExitCode
}

function Get-LogMutexName([string]$LogFilePath) {
    # The mutex name is derived from the log path so concurrent deployments writing to distinct logs never serialize each other
    # The Global prefix lets two backends started from different sessions share the same mutex
    # SHA1CryptoServiceProvider is a FIPS-validated implementation, so the hash also works on machines enforcing the FIPS policy
    try {
        $sha1Provider = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
        try { $hashBytes = $sha1Provider.ComputeHash([Text.Encoding]::UTF8.GetBytes($LogFilePath.ToLowerInvariant())) } finally { $sha1Provider.Clear() }
        $hexBuilder = New-Object Text.StringBuilder
        foreach ($hashByte in $hashBytes) { [void]$hexBuilder.Append($hashByte.ToString('x2')) }
        return ("Global\CloseProcessPopup_" + $hexBuilder.ToString())
    } catch {
        $sanitizedPath = ($LogFilePath.ToLowerInvariant() -replace '[^a-z0-9]','_')
        if ($sanitizedPath.Length -gt 200) { $sanitizedPath = $sanitizedPath.Substring($sanitizedPath.Length - 200) }
        return ("Global\CloseProcessPopup_" + $sanitizedPath)
    }
}

function Open-LogMutex([string]$MutexName) {
    # The named mutex serializes the backends sharing one log file. When it cannot be created or opened,
    # an anonymous mutex still serializes the threads of this process (main thread and pipe reader runspaces)
    try { return New-Object System.Threading.Mutex($false,$MutexName) }
    catch {
        try { return [System.Threading.Mutex]::OpenExisting($MutexName) }
        catch { return New-Object System.Threading.Mutex($false) }
    }
}

function Write-CustomLog { param([string]$Message, [switch]$NoPrefix)
    $logLine = $Message
    if (-not $NoPrefix.IsPresent) { $logLine = (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff") + " - " + $Message }
    # An abandoned mutex still grants ownership to the caller, so the exception is treated as a successful acquisition
    $mutexAcquired = $false
    $streamWriter = $null
    try {
        if ($script:LogMutex) { try { $mutexAcquired = $script:LogMutex.WaitOne(3000) } catch [System.Threading.AbandonedMutexException] { $mutexAcquired = $true } }
        $streamWriter = New-Object IO.StreamWriter($script:LogPath, $true, [Text.Encoding]::UTF8)
        $streamWriter.WriteLine($logLine)
    } catch {} finally {
        if ($streamWriter) { $streamWriter.Close() }
        if ($mutexAcquired) { try { $script:LogMutex.ReleaseMutex() } catch {} }
    }
    Write-Host $logLine
}

function Format-Name([string]$RawName) {
    # Turns a display name into a string that is safe inside a file name
    $safeName = $RawName.Trim()
    $invalidCharacters = [IO.Path]::GetInvalidFileNameChars() + [IO.Path]::GetInvalidPathChars()
    foreach ($invalidCharacter in $invalidCharacters) { $safeName = $safeName.Replace([string]$invalidCharacter, "_") }
    if ([string]::IsNullOrEmpty($safeName)) { $safeName = "Software" }
    elseif ($safeName.Length -gt 200) { $safeName = $safeName.Substring(0,200) }
    return $safeName
}

function Resolve-LogPath([string]$Title,[string]$CandidateLog) {
    # Defines the log file path and creates its folder when missing
    $defaultName = "${Title}_CloseProcessPopup.log"
    $defaultFolder = Join-Path $script:WindowsDirectory "Temp"
    if ([string]::IsNullOrEmpty($CandidateLog)) { $logFilePath = Join-Path $defaultFolder $defaultName }
    elseif ($CandidateLog -match '[\\/]' -and (Test-Path -LiteralPath $CandidateLog -PathType Container)) { $logFilePath = Join-Path $CandidateLog $defaultName }
    else {
        $leafName = if ($CandidateLog -match '[\\/]') { [IO.Path]::GetFileName($CandidateLog) } else { $CandidateLog }
        if ($leafName -notmatch 'popup') { $leafName = [IO.Path]::GetFileNameWithoutExtension($leafName) + "_CloseProcessPopup" + [IO.Path]::GetExtension($leafName) }
        if ([string]::IsNullOrEmpty([IO.Path]::GetExtension($leafName))) { $leafName += ".log" }
        $parentFolder = if ($CandidateLog -match '[\\/]') { Split-Path $CandidateLog -Parent } else { $null }
        if (-not $parentFolder) { $parentFolder = $defaultFolder }
        $logFilePath = Join-Path $parentFolder $leafName
    }
    $logFolder = [IO.Path]::GetDirectoryName($logFilePath)
    if (-not (Test-Path -LiteralPath $logFolder -PathType Container)) { New-Item -Path $logFolder -Type Directory -Force | Out-Null }
    return $logFilePath
}

function Close-NativeHandle([IntPtr[]]$Handles) {
    foreach ($nativeHandle in $Handles) {
        if ($nativeHandle -ne [IntPtr]::Zero) { try { [void][Win32Api]::CloseHandle($nativeHandle) } catch {} }
    }
}

function Enable-Privilege([string]$PrivilegeName) {
    # Returns $true only when the privilege is really enabled : AdjustTokenPrivileges also succeeds when the token does not hold the privilege
    $TOKEN_ADJUST_PRIVILEGES=0x20; $TOKEN_QUERY=0x8; $SE_PRIVILEGE_ENABLED=0x2
    $processTokenHandle=[IntPtr]::Zero
    if(-not [AdvApi32]::OpenProcessToken([Win32Api]::GetCurrentProcess(),($TOKEN_ADJUST_PRIVILEGES -bor $TOKEN_QUERY),[ref]$processTokenHandle)){ return $false }
    try{
        $privilegeLuid=New-Object LUID
        if(-not [AdvApi32]::LookupPrivilegeValue($null,$PrivilegeName,[ref]$privilegeLuid)){ return $false }
        $luidAndAttributes=New-Object LUID_AND_ATTRIBUTES
        $luidAndAttributes.Luid=$privilegeLuid; $luidAndAttributes.Attributes=$SE_PRIVILEGE_ENABLED
        $tokenPrivileges=New-Object TOKEN_PRIVILEGES
        $tokenPrivileges.PrivilegeCount=1; $tokenPrivileges.Privileges=$luidAndAttributes
        if(-not [AdvApi32]::AdjustTokenPrivileges($processTokenHandle,$false,[ref]$tokenPrivileges,0,[IntPtr]::Zero,[IntPtr]::Zero)){ return $false }
        return ([Runtime.InteropServices.Marshal]::GetLastWin32Error() -eq 0)
    } finally { Close-NativeHandle @($processTokenHandle) }
}

function Get-ProcessSessionId([int]$ProcessId) {
    $processSessionId = 0
    try { if ([Win32Api]::ProcessIdToSessionId($ProcessId,[ref]$processSessionId)) { return [int]$processSessionId } } catch {}
    return -1
}

function Open-ProcessTargetHandle([int]$ProcessId) {
    # Holding an open handle pins the kernel process object : Windows cannot recycle the PID while the handle exists,
    # so terminating or awaiting through this handle always addresses the process observed at detection time
    # A wait-only handle is requested when the terminate right is denied, so the exit can still be awaited after a taskkill fallback
    $targetHandle = [IntPtr]::Zero
    $canTerminate = $false
    try { $targetHandle = [Win32Api]::OpenProcess([uint32]($script:ProcessAccess.Terminate -bor $script:ProcessAccess.Synchronize),$false,$ProcessId) } catch { $targetHandle = [IntPtr]::Zero }
    if ($targetHandle -ne [IntPtr]::Zero) { $canTerminate = $true }
    else { try { $targetHandle = [Win32Api]::OpenProcess([uint32]$script:ProcessAccess.Synchronize,$false,$ProcessId) } catch { $targetHandle = [IntPtr]::Zero } }
    return @{ ProcessId=$ProcessId; Handle=$targetHandle; CanTerminate=$canTerminate; SessionId=(Get-ProcessSessionId $ProcessId) }
}

function Close-TargetItemHandle([object[]]$Items) {
    # Releases the pinned process handles so the kernel can reclaim the process objects and recycle the PIDs
    foreach ($targetItem in $Items) {
        if (-not $targetItem) { continue }
        foreach ($processTarget in $targetItem.Targets) {
            if ($processTarget -and $processTarget.Handle -ne [IntPtr]::Zero) { Close-NativeHandle @($processTarget.Handle); $processTarget.Handle = [IntPtr]::Zero }
        }
    }
}

function ConvertTo-Base64Png([System.Drawing.Icon]$Icon) {
    if (-not $Icon) { return $null }
    $iconBitmap = $Icon.ToBitmap()
    $pngStream  = New-Object IO.MemoryStream
    try {
        $iconBitmap.Save($pngStream,[System.Drawing.Imaging.ImageFormat]::Png)
        return [Convert]::ToBase64String($pngStream.ToArray())
    } catch { return $null } finally { $pngStream.Dispose(); $iconBitmap.Dispose() }
}


# ==================================================================
#                     CRITICAL PROCESS PROTECTION
# ==================================================================

# Executables whose termination destabilizes Windows. A process from this list is only terminated when it was requested by its exact name
$script:CriticalProcessNames = @{}
foreach ($criticalProcessName in @(
    # Core Windows kernel and session processes
    'smss.exe','csrss.exe','wininit.exe','winlogon.exe','services.exe','lsass.exe','lsaiso.exe','lsm.exe',
    # Service hosting
    'svchost.exe','sihost.exe','taskhostw.exe','taskhost.exe','taskhostex.exe','runtimebroker.exe','dllhost.exe','backgroundtaskhost.exe','backgroundtransferhost.exe',
    # Desktop and shell
    'dwm.exe','explorer.exe','conhost.exe','ctfmon.exe','fontdrvhost.exe','audiodg.exe',
    'applicationframehost.exe','shellexperiencehost.exe','startmenuexperiencehost.exe','textinputhost.exe','systemsettings.exe','systemsettingsbroker.exe','settingsynchost.exe',
    'searchui.exe','searchapp.exe','searchhost.exe','searchindexer.exe','searchfilterhost.exe','searchprotocolhost.exe',
    'phoneexperiencehost.exe','gamebarpresencewriter.exe','gamebar.exe','gamebarftserver.exe',
    # Windows Security / Defender
    'msmpeng.exe','nissrv.exe','mssense.exe','sensecncproxy.exe','securityhealthservice.exe','securityhealthhost.exe','securityhealthsystray.exe','smartscreen.exe','sgrmbroker.exe',
    # Credential and authentication
    'logonui.exe','userinit.exe','consent.exe','credentialuibroker.exe','lockapp.exe','credentialenrollmentmanager.exe',
    # Windows Update, servicing and installer
    'trustedinstaller.exe','tiworker.exe','usoclient.exe','usocoreworker.exe','mousocoreworker.exe','wuauclt.exe','musnotification.exe','musnotificationux.exe','waasmedicagent.exe','msiexec.exe',
    # Print spooler
    'spoolsv.exe','printfilterpipelinesvc.exe',
    # WMI and COM
    'wmiprvse.exe','unsecapp.exe','wmiapsrv.exe','scrcons.exe','msdtc.exe',
    # Device and hardware
    'dashost.exe','devicecensus.exe','deviceenroller.exe','wudfhost.exe',
    # Remote Desktop
    'rdpclip.exe','rdpinput.exe','rdpsa.exe','rdpshell.exe','tstheme.exe',
    # Error reporting, compatibility and telemetry
    'werfault.exe','werfaultsecure.exe','wermgr.exe','compattelrunner.exe','microsoftedgeupdate.exe',
    # Hyper-V, virtualization and WSL
    'vmwp.exe','vmms.exe','vmcompute.exe','vmmem.exe','vmconnect.exe','wsl.exe','wslhost.exe','wslservice.exe',
    # Input and accessibility
    'tabtip.exe','inputpersonalization.exe','atbroker.exe','narrator.exe','magnify.exe','osk.exe','utilman.exe',
    # Storage, licensing and speech
    'vds.exe','vdsldr.exe','defrag.exe','disksnapshot.exe','clipup.exe','licensingdiag.exe','speechruntime.exe',
    # Server roles
    'dns.exe',
    # Graphics drivers and vendor services
    'igfxem.exe','igfxcuiservice.exe','igfxhk.exe','igfxtray.exe','nvcontainer.exe','nvdisplay.container.exe','nvspcaps64.exe','nvcplui.exe',
    'atieclxx.exe','atiesrxx.exe','amdow.exe','amddvr.exe','radeonsoftware.exe','intelcphecisvc.exe','jhi_service.exe','iastordatamgrsvc.exe'
)) { $script:CriticalProcessNames[$criticalProcessName] = $true }

# Directories whose executables are never terminated when they were matched through a path or a DLL pattern
# ProgramData and ProgramFiles(x86) do not exist on every system and Join-Path throws on a null Path argument
$script:ProtectedSystemPaths = @(@(
    $script:WindowsDirectory,
    $(if ($env:ProgramData) { Join-Path $env:ProgramData "Microsoft\Windows Defender" }),
    $(if ($env:ProgramFiles) { Join-Path $env:ProgramFiles "Windows Defender" }),
    $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} "Windows Defender" }),
    $(if ($env:ProgramFiles) { Join-Path $env:ProgramFiles "Windows Security" }),
    $(if ($env:ProgramFiles) { Join-Path $env:ProgramFiles "WindowsApps" })
) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -ErrorAction SilentlyContinue) } | ForEach-Object { $_.ToLowerInvariant().TrimEnd('\') })

function Get-CriticalProcessReason([string]$ProcessNameLower,[string]$ExecutablePath,[string]$Source) {
    # Returns the reason why a process must not be terminated, or nothing when it may be
    # An exact -Process name is a deliberate operator decision and bypasses the protection, a wildcard is not
    if ($Source -eq 'Explicit') { return }
    if ($script:CriticalProcessNames.ContainsKey($ProcessNameLower)) { return "Process name is in the critical system processes list" }
    if (($Source -eq 'DLL' -or $Source -eq 'Path') -and $ExecutablePath) {
        $executableFolderLower = [IO.Path]::GetDirectoryName($ExecutablePath.ToLowerInvariant())
        if ($executableFolderLower) {
            $executableFolderLower = $executableFolderLower.TrimEnd('\')
            foreach ($protectedPath in $script:ProtectedSystemPaths) {
                if ($executableFolderLower -eq $protectedPath -or $executableFolderLower.StartsWith($protectedPath + '\')) { return "Process executable is located in protected system directory ($protectedPath)" }
            }
        }
    }
}


# ==================================================================
#                              DISCOVERY
# ==================================================================

function Get-SessionInformationString([int]$SessionId,[int]$InformationClass) {
    $bufferPointer = [IntPtr]::Zero; $bytesReturned = 0
    if (-not [WtsApi32]::WTSQuerySessionInformation([IntPtr]::Zero,$SessionId,$InformationClass,[ref]$bufferPointer,[ref]$bytesReturned)) { return "" }
    try { return [string][Runtime.InteropServices.Marshal]::PtrToStringUni($bufferPointer) } finally { [WtsApi32]::WTSFreeMemory($bufferPointer) }
}

function Get-SessionContext {
    # Describes the current process and lists every active session that has a logged-on user (console and RDP alike)
    $currentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $sessionContext = @{
        Name                    = $currentIdentity.Name
        IsSystem                = $currentIdentity.IsSystem
        IsAdmin                 = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        IsProcessInteractive    = [Environment]::UserInteractive
        CurrentProcessSessionId = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        ActiveUserSessions      = @()
    }
    $sessionsPointer = [IntPtr]::Zero; $sessionCount = 0
    try {
        if (-not [WtsApi32]::WTSEnumerateSessions([IntPtr]::Zero,0,1,[ref]$sessionsPointer,[ref]$sessionCount)) { throw ("WTSEnumerateSessions failed, error=" + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
        $structSize = [Runtime.InteropServices.Marshal]::SizeOf([type]([WTS_SESSION_INFO]))
        $cursorPointer = $sessionsPointer
        for ($sessionIndex=0; $sessionIndex -lt $sessionCount; $sessionIndex++) {
            $sessionInfo = [Runtime.InteropServices.Marshal]::PtrToStructure($cursorPointer,[type]([WTS_SESSION_INFO]))
            $cursorPointer = New-Object IntPtr ($cursorPointer.ToInt64() + $structSize)
            $stationName = [Runtime.InteropServices.Marshal]::PtrToStringUni($sessionInfo.pWinStationName)
            # State 0 is WTSActive. The Services station is session 0, a session without user name is a logon screen
            if ($sessionInfo.State -ne 0 -or $stationName -eq 'Services') { continue }
            $userName = Get-SessionInformationString -SessionId $sessionInfo.SessionId -InformationClass 5
            if ([string]::IsNullOrEmpty($userName)) { continue }
            $domainName = Get-SessionInformationString -SessionId $sessionInfo.SessionId -InformationClass 7
            $fullName = $userName
            if (-not [string]::IsNullOrEmpty($domainName)) { $fullName = $domainName + "\" + $userName }
            $sessionContext.ActiveUserSessions += ,@{ SessionId=[int]$sessionInfo.SessionId; Station=$stationName; UserName=$userName; Domain=$domainName; FullName=$fullName }
        }
    } catch {
        Write-CustomLog ("Session enumeration failed : " + $_.Exception.Message)
        Stop-Script 6
    } finally {
        if ($sessionsPointer -ne [IntPtr]::Zero) { [WtsApi32]::WTSFreeMemory($sessionsPointer) }
    }
    return $sessionContext
}

function Resolve-SearchCriteria {
    <#
    Purpose : Normalize the command line arguments once, so every scan pass applies exactly the same criteria.
    - -Process supports "*" and "?" wildcards on executable names ("chrome*.exe", "win* = My caption").
    - -ProcessPath is a wildcard pattern on the full executable path ; without wildcard it is a single .exe or a folder searched recursively.
    - -ProcessDLL is a wildcard pattern on a module file name, or on a module full path when it contains a path separator.
    - -ProcessTitle is a wildcard pattern on a window title ; "TitlePattern=ProcessNamePattern" restricts it to matching executables.
    #>
    param([string[]]$Processes,[string[]]$ProcessesPaths,[string[]]$ProcessTitles,[string[]]$ProcessDLL)
    $explicitNames=@{}; $namePatterns=@(); $pathPatterns=@(); $dllPatterns=@(); $titleQueries=@()
    foreach($rawArgument in $Processes){
        if([string]::IsNullOrEmpty($rawArgument)){continue}
        $executableNameRaw=$rawArgument; $descriptionText=""
        if($rawArgument -like "*=*"){ $nameAndDescription=$rawArgument -split "=",2; $executableNameRaw=$nameAndDescription[0]; $descriptionText=$nameAndDescription[1].Trim() }
        $executableName=[IO.Path]::GetFileName($executableNameRaw.Trim('"',' ','\','/'))
        if([string]::IsNullOrEmpty($executableName)){continue}
        if($executableName -notmatch '\.exe$'){ $executableName+='.exe' }
        $lowerName=$executableName.ToLowerInvariant()
        # The wildcard characters are escaped inside the -like test patterns, otherwise *?* would match any non-empty string
        if($lowerName -like '*[*]*' -or $lowerName -like '*[?]*'){ $namePatterns+=,@{PatternLower=$lowerName;Description=$descriptionText} }
        elseif(-not $explicitNames.ContainsKey($lowerName)){ $explicitNames[$lowerName]=@{Name=$executableName;Description=$descriptionText} }
    }
    foreach($pathArgument in $ProcessesPaths){
        if([string]::IsNullOrEmpty($pathArgument)){continue}
        $rawPath=$pathArgument.Trim().Trim('"')
        if([string]::IsNullOrEmpty($rawPath)){continue}
        $fullPath=$rawPath
        try{ $fullPath=[IO.Path]::GetFullPath($rawPath) }catch{}
        $pathPatternLower=($fullPath -replace '/','\').ToLowerInvariant()
        $hasWildcard=($pathPatternLower -like '*[*]*' -or $pathPatternLower -like '*[?]*')
        if(-not $hasWildcard -and $pathPatternLower -notmatch '\.exe$'){ $pathPatternLower=$pathPatternLower.TrimEnd('\') + '\*' }
        $pathPatterns+=,@{PatternLower=$pathPatternLower;RawInput=$rawPath}
    }
    foreach($dllArgument in $ProcessDLL){
        if([string]::IsNullOrEmpty($dllArgument)){continue}
        $trimmedDllPattern=$dllArgument.Trim()
        if([string]::IsNullOrEmpty($trimmedDllPattern)){continue}
        $dllPatterns+=,@{PatternLower=$trimmedDllPattern.ToLowerInvariant();UseFileNameOnly=(-not ($trimmedDllPattern -match '[\\/]'))}
    }
    foreach($titleArgument in $ProcessTitles){
        if([string]::IsNullOrEmpty($titleArgument)){continue}
        $titlePattern=$titleArgument.Trim(); $processNamePattern=""
        if($titleArgument -like "*=*"){
            $titleAndProcessName=$titleArgument -split "=",2
            $titlePattern=$titleAndProcessName[0].Trim()
            $processNamePattern=[IO.Path]::GetFileName($titleAndProcessName[1].Trim())
            if($processNamePattern -and ($processNamePattern -notmatch '\.exe$')){ $processNamePattern+='.exe' }
        }
        if([string]::IsNullOrEmpty($titlePattern)){continue}
        $titleQueries+=,@{TitlePatternLower=$titlePattern.ToLowerInvariant();ProcNamePatternLower=$processNamePattern.ToLowerInvariant()}
    }
    if($explicitNames.Count -gt 0){ Write-CustomLog ("Process names : " + ((@($explicitNames.Keys) | Sort-Object) -join "; ")) }
    if($namePatterns.Count -gt 0){ Write-CustomLog ("Process name patterns : " + ((@($namePatterns | ForEach-Object { $_.PatternLower })) -join "; ")) }
    if($pathPatterns.Count -gt 0){ Write-CustomLog ("ProcessPath patterns : " + ((@($pathPatterns | ForEach-Object { $_.PatternLower })) -join "; ")) }
    if($dllPatterns.Count -gt 0){ Write-CustomLog ("DLL patterns : " + ((@($dllPatterns | ForEach-Object { $_.PatternLower })) -join "; ")) }
    if($titleQueries.Count -gt 0){ Write-CustomLog ("Title patterns : " + ((@($titleQueries | ForEach-Object { $_.TitlePatternLower })) -join "; ")) }
    return @{ ExplicitNames=$explicitNames; NamePatterns=$namePatterns; PathPatterns=$pathPatterns; DllPatterns=$dllPatterns; TitleQueries=$titleQueries }
}

function Get-AllProcessId {
    # The buffer doubles until EnumProcesses leaves free room, which is the only way to know that the list is complete
    # Returns nothing when the enumeration fails
    $bufferLength=2048
    while($true){
        $processIdBuffer=New-Object int[] $bufferLength
        $bytesReturned=0
        if(-not [Win32Api]::EnumProcesses($processIdBuffer,$bufferLength*4,[ref]$bytesReturned)){ return }
        $processCount=[int]($bytesReturned/4)
        if($processCount -lt $bufferLength){
            $allProcessIds=New-Object int[] $processCount
            [Array]::Copy($processIdBuffer,$allProcessIds,$processCount)
            return ,$allProcessIds
        }
        $bufferLength=$bufferLength*2
    }
}

function Get-ProcessImagePath([int]$ProcessId) {
    # Returns the full executable path of a process, or nothing when the process cannot be opened
    # PROCESS_QUERY_LIMITED_INFORMATION is granted on far more processes than PROCESS_QUERY_INFORMATION, it exists since Windows Vista
    $isVistaOrLater=([Environment]::OSVersion.Version.Major -ge 6)
    $queryAccess=$script:ProcessAccess.QueryInformation
    if($isVistaOrLater){ $queryAccess=$script:ProcessAccess.QueryLimitedInformation }
    $queryHandle=[IntPtr]::Zero
    try{
        $queryHandle=[Win32Api]::OpenProcess([uint32]$queryAccess,$false,$ProcessId)
        if($queryHandle -eq [IntPtr]::Zero){ return }
        if($isVistaOrLater){
            $pathBuilder=New-Object System.Text.StringBuilder 1024
            $pathLength=$pathBuilder.Capacity
            if([Win32Api]::QueryFullProcessImageName($queryHandle,0,$pathBuilder,[ref]$pathLength)){ return $pathBuilder.ToString() }
        }
        $wmiProcess=Get-WmiObject -Class Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop
        if($wmiProcess -and $wmiProcess.ExecutablePath){ return $wmiProcess.ExecutablePath }
        if($wmiProcess){ return $wmiProcess.Name }
    } catch {} finally { Close-NativeHandle @($queryHandle) }
}

function Get-MatchingModule {
    # Returns the modules of a process that match one of the DLL patterns
    # LIST_MODULES_ALL (0x03) also returns the modules of 32-bit WOW64 processes when called from a 64-bit process
    param([int]$ProcessId,[object[]]$DllPatterns,[hashtable]$ScanStatistics)
    $matchedModules=@()
    $inspectionHandle=[IntPtr]::Zero
    try{
        $inspectionHandle=[Win32Api]::OpenProcess([uint32]($script:ProcessAccess.QueryInformation -bor $script:ProcessAccess.VmRead),$false,$ProcessId)
        if($inspectionHandle -eq [IntPtr]::Zero){ $ScanStatistics.UninspectedProcessCount=$ScanStatistics.UninspectedProcessCount+1; return ,$matchedModules }
        $pointerSize=[IntPtr]::Size
        $moduleHandles=New-Object IntPtr[] 512
        $bufferBytes=$moduleHandles.Length*$pointerSize
        $requiredBytes=0
        $isEnumerated=[Win32Api]::EnumProcessModulesEx($inspectionHandle,$moduleHandles,$bufferBytes,[ref]$requiredBytes,[uint32]3)
        if($isEnumerated -and $requiredBytes -gt $bufferBytes){
            $moduleHandles=New-Object IntPtr[] ([int][math]::Ceiling($requiredBytes/[double]$pointerSize))
            $bufferBytes=$moduleHandles.Length*$pointerSize
            $isEnumerated=[Win32Api]::EnumProcessModulesEx($inspectionHandle,$moduleHandles,$bufferBytes,[ref]$requiredBytes,[uint32]3)
        }
        if(-not $isEnumerated){
            $ScanStatistics.LastModuleEnumerationError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $ScanStatistics.ModuleEnumerationFailureCount=$ScanStatistics.ModuleEnumerationFailureCount+1
            return ,$matchedModules
        }
        $moduleCount=[int]([math]::Min($requiredBytes,$bufferBytes)/$pointerSize)
        $modulePathBuilder=New-Object System.Text.StringBuilder 1024
        for($moduleIndex=0;$moduleIndex -lt $moduleCount;$moduleIndex++){
            [void]$modulePathBuilder.Remove(0,$modulePathBuilder.Length)
            [void][Win32Api]::GetModuleFileNameEx($inspectionHandle,$moduleHandles[$moduleIndex],$modulePathBuilder,[uint32]$modulePathBuilder.Capacity)
            $modulePath=$modulePathBuilder.ToString()
            if([string]::IsNullOrEmpty($modulePath)){continue}
            $modulePathLower=$modulePath.ToLowerInvariant()
            $moduleFileLower=[System.IO.Path]::GetFileName($modulePathLower)
            foreach($dllPattern in $DllPatterns){
                if($dllPattern.UseFileNameOnly){ if($moduleFileLower -like $dllPattern.PatternLower){ $matchedModules+=,$moduleFileLower; break } }
                elseif($modulePathLower -like $dllPattern.PatternLower){ $matchedModules+=,$modulePath; break }
            }
        }
        return ,$matchedModules
    } catch { return ,$matchedModules } finally { Close-NativeHandle @($inspectionHandle) }
}

function Find-TargetProcess {
    <#
    Purpose : One detection pass over the running processes (EnumProcesses) and, unless -SkipTitles, over the windows of the user sessions.
    - Only the processes that really match are targeted : a path or DLL match never extends to the other processes sharing the same executable name.
    - Every targeted process gets a pinned handle (see Open-ProcessTargetHandle), which makes termination immune to PID recycling.
    - The function only reports : deciding what a critical match or an empty result means belongs to the caller.
    Returns nothing when the processes cannot be enumerated, otherwise :
        @{ Items=@( @{ Key; Name; ShortName; Description; ExePath; IconBase64; Source; SourceDetail; SessionId; Targets=@(@{ProcessId;Handle;CanTerminate;SessionId}); CriticalReason } ); MissingExplicitNames=@() }
        Source is Explicit (exact name), Pattern (wildcard name), Path, DLL or Title. SessionId is only set for Title items.
    #>
    param([hashtable]$SearchCriteria,[hashtable]$SessionContext,[hashtable]$ExcludedProcessIds,[switch]$SkipTitles,[switch]$Quiet)
    $itemsByKey=@{}; $itemKeysInOrder=@(); $foundExplicitNames=@{}
    $scanStatistics=@{ UninspectedProcessCount=0; ModuleEnumerationFailureCount=0; LastModuleEnumerationError=0 }
    $isDllScanRequested=($SearchCriteria.DllPatterns.Count -gt 0)
    $allProcessIds=Get-AllProcessId
    if($null -eq $allProcessIds){ return }
    # 1) -------------- Name, path and DLL matching over a single process enumeration --------------
    foreach($processId in $allProcessIds){
        if($processId -eq 0){continue}
        $processFullPath=Get-ProcessImagePath -ProcessId $processId
        if([string]::IsNullOrEmpty($processFullPath)){continue}
        $processName=[System.IO.Path]::GetFileName($processFullPath)
        $lowerName=$processName.ToLowerInvariant()
        $shortName=($processName -replace '\.exe$','')
        $source=$null; $sourceDetail=$null; $description=$shortName
        if($SearchCriteria.ExplicitNames.ContainsKey($lowerName)){ $source='Explicit'; $description=$SearchCriteria.ExplicitNames[$lowerName].Description; $foundExplicitNames[$lowerName]=$true }
        if(-not $source){
            foreach($namePattern in $SearchCriteria.NamePatterns){
                if($lowerName -like $namePattern.PatternLower){ $source='Pattern'; $sourceDetail=$namePattern.PatternLower; $description=$namePattern.Description; break }
            }
        }
        if(-not $source -and $SearchCriteria.PathPatterns.Count -gt 0){
            $processPathLower=($processFullPath -replace '/','\').ToLowerInvariant()
            foreach($pathPattern in $SearchCriteria.PathPatterns){
                if($processPathLower -like $pathPattern.PatternLower){ $source='Path'; $sourceDetail=$pathPattern.RawInput; break }
            }
        }
        if(-not $source -and $isDllScanRequested){
            $matchedModules=Get-MatchingModule -ProcessId $processId -DllPatterns $SearchCriteria.DllPatterns -ScanStatistics $scanStatistics
            if($matchedModules.Count -gt 0){ $source='DLL'; $sourceDetail=((@($matchedModules | Select-Object -First 3)) -join ", ") }
        }
        if(-not $source){continue}
        if($ExcludedProcessIds -and $ExcludedProcessIds.ContainsKey($processId)){
            if(-not $Quiet){ Write-CustomLog ("WARNING : PID {0} ({1}) matches the request but hosts this script, it is left running" -f $processId,$processName) }
            continue
        }
        if(-not $itemsByKey.ContainsKey($lowerName)){
            $itemsByKey[$lowerName]=@{ Key=$lowerName; Name=$processName; ShortName=$shortName; Description=$description; ExePath=$processFullPath; IconBase64=$null; Source=$source; SourceDetail=$sourceDetail; SessionId=$null; Targets=@(); CriticalReason=$null }
            $itemKeysInOrder+=,$lowerName
        }
        $targetItem=$itemsByKey[$lowerName]
        $targetItem.Targets+=,(Open-ProcessTargetHandle -ProcessId $processId)
        if(-not $targetItem.CriticalReason){ $targetItem.CriticalReason=Get-CriticalProcessReason -ProcessNameLower $lowerName -ExecutablePath $processFullPath -Source $source }
    }
    if(-not $Quiet -and $scanStatistics.UninspectedProcessCount -gt 0){ Write-CustomLog ("DLL scan : {0} processes could not be opened for module inspection (protected or access denied)" -f $scanStatistics.UninspectedProcessCount) }
    if(-not $Quiet -and $scanStatistics.ModuleEnumerationFailureCount -gt 0){ Write-CustomLog ("DLL scan : module enumeration failed for {0} processes (last error={1}, 299 means a 32-bit scanner facing a 64-bit process)" -f $scanStatistics.ModuleEnumerationFailureCount,$scanStatistics.LastModuleEnumerationError) }
    # 2) -------------- Title matching over the windows of the user sessions --------------
    if(-not $SkipTitles -and $SearchCriteria.TitleQueries.Count -gt 0){
        $windowEntries=Get-UserSessionWindow -SearchCriteria $SearchCriteria -SessionContext $SessionContext
        foreach($windowEntry in $windowEntries){
            if($ExcludedProcessIds -and $ExcludedProcessIds.ContainsKey($windowEntry.ProcessId)){ continue }
            $windowProcessName=$windowEntry.Name
            $windowProcessNameLower=$windowProcessName.ToLowerInvariant()
            $titleItemKey=("title|" + $windowEntry.SessionId + "|" + $windowProcessNameLower + "|" + $windowEntry.Title.ToLowerInvariant())
            if(-not $itemsByKey.ContainsKey($titleItemKey)){
                $itemsByKey[$titleItemKey]=@{ Key=$titleItemKey; Name=$windowProcessName; ShortName=($windowProcessName -replace '\.exe$',''); Description=$windowEntry.Title; ExePath=$windowEntry.ExePath; IconBase64=$windowEntry.IconBase64; Source='Title'; SourceDetail=$windowEntry.Title; SessionId=$windowEntry.SessionId; Targets=@(); CriticalReason=$null }
                $itemKeysInOrder+=,$titleItemKey
            }
            $targetItem=$itemsByKey[$titleItemKey]
            $isAlreadyTargeted=$false
            foreach($existingTarget in $targetItem.Targets){ if($existingTarget.ProcessId -eq $windowEntry.ProcessId){ $isAlreadyTargeted=$true; break } }
            if($isAlreadyTargeted){ continue }
            # The handle is opened by this backend process because kernel handles are per-process objects
            $targetItem.Targets+=,(Open-ProcessTargetHandle -ProcessId $windowEntry.ProcessId)
            if(-not $targetItem.CriticalReason){ $targetItem.CriticalReason=Get-CriticalProcessReason -ProcessNameLower $windowProcessNameLower -ExecutablePath $windowEntry.ExePath -Source 'Title' }
        }
    }
    # 3) -------------- Result --------------
    $foundItems=@(); foreach($itemKey in $itemKeysInOrder){ $foundItems+=,$itemsByKey[$itemKey] }
    $missingExplicitNames=@()
    foreach($explicitNameLower in @($SearchCriteria.ExplicitNames.Keys)){ if(-not $foundExplicitNames.ContainsKey($explicitNameLower)){ $missingExplicitNames+=,$SearchCriteria.ExplicitNames[$explicitNameLower].Name } }
    return @{ Items=$foundItems; MissingExplicitNames=$missingExplicitNames }
}

function Write-ScanReport([hashtable]$ScanResult) {
    Write-CustomLog ("Items found : count=" + $ScanResult.Items.Count)
    if($ScanResult.Items.Count -gt 0){ Write-CustomLog " Running found :" -NoPrefix }
    foreach($targetItem in $ScanResult.Items){
        $processIdsDisplay=(@($targetItem.Targets | ForEach-Object { $_.ProcessId })) -join ","
        $sourceLabel=$targetItem.Source.ToUpper()
        if($targetItem.Source -eq 'Path'){ $reportBlock=(" -> [{0}] {1}`n     Match : {2}`n     PIDs : {3}" -f $sourceLabel,$targetItem.Name,$targetItem.ExePath,$processIdsDisplay) }
        elseif($targetItem.Source -eq 'DLL'){ $reportBlock=(" -> [{0}] {1}`n     DLL : {2}`n     Process : {3}`n     PIDs : {4}" -f $sourceLabel,$targetItem.Name,$targetItem.SourceDetail,$targetItem.ExePath,$processIdsDisplay) }
        elseif($targetItem.Source -eq 'Title'){ $reportBlock=(" -> [{0}] {1}`n     Title : {2}`n     Session : {3}`n     Process : {4}`n     PIDs : {5}" -f $sourceLabel,$targetItem.Name,$targetItem.Description,$targetItem.SessionId,$targetItem.ExePath,$processIdsDisplay) }
        else{ $reportBlock=(" -> [{0}] {1}`n     Source : {2}`n     PIDs : {3}" -f $sourceLabel,$targetItem.Name,$targetItem.ExePath,$processIdsDisplay) }
        Write-CustomLog "$reportBlock`n------" -NoPrefix
    }
    if($ScanResult.MissingExplicitNames.Count -gt 0){ Write-CustomLog (" Not running : " + ((@($ScanResult.MissingExplicitNames | Sort-Object -Unique)) -join ", ")) -NoPrefix }
}

function Write-CriticalMatchReport([object[]]$CriticalItems) {
    Write-CustomLog "===================================================================="
    Write-CustomLog "CRITICAL ERROR : System-essential processes detected - CANNOT PROCEED"
    Write-CustomLog "===================================================================="
    Write-CustomLog ""
    Write-CustomLog "The following processes were matched but cannot be terminated :"
    Write-CustomLog ""
    foreach ($criticalItem in $CriticalItems) {
        Write-CustomLog ("  Process  : {0}" -f $criticalItem.Name)
        Write-CustomLog ("  Source   : {0}" -f $criticalItem.Source.ToUpper())
        if ($criticalItem.SourceDetail) { Write-CustomLog ("  Matched  : {0}" -f $criticalItem.SourceDetail) }
        if ($criticalItem.ExePath) { Write-CustomLog ("  Path     : {0}" -f $criticalItem.ExePath) }
        Write-CustomLog ("  PIDs     : {0}" -f ((@($criticalItem.Targets | ForEach-Object { $_.ProcessId })) -join ", "))
        Write-CustomLog ("  Reason   : {0}" -f $criticalItem.CriticalReason)
        Write-CustomLog "  ---"
    }
    Write-CustomLog ""
    Write-CustomLog "RECOMMENDATION :"
    Write-CustomLog "  - If using -Process with a wildcard : narrow the pattern, or name the process exactly to terminate it on purpose."
    Write-CustomLog "  - If using -ProcessDLL : ensure the DLL is not a common system library, avoid patterns that match Windows components."
    Write-CustomLog "  - If using -ProcessPath : target only the installation directory of the application, never a system directory."
    Write-CustomLog ""
    Write-CustomLog "Aborting to prevent system instability. Exit code : 16"
}

function Add-TargetItemIcon([object[]]$Items) {
    # Attaches a Base64 PNG icon to the items that have none (window based items receive theirs from the user session)
    Add-Type -AssemblyName System.Drawing
    $iconCacheByExePathLower=@{}
    $defaultIconBase64=ConvertTo-Base64Png ([System.Drawing.SystemIcons]::Application)
    foreach($targetItem in $Items){
        if(-not $targetItem -or $targetItem.IconBase64){ continue }
        $iconBase64=$null
        if($targetItem.ExePath -and (Test-Path -LiteralPath $targetItem.ExePath)){
            $exePathLower=$targetItem.ExePath.ToLowerInvariant()
            if(-not $iconCacheByExePathLower.ContainsKey($exePathLower)){
                $extractedIconBase64=$null
                try{ $extractedIconBase64=ConvertTo-Base64Png ([System.Drawing.Icon]::ExtractAssociatedIcon($targetItem.ExePath)) }catch{}
                $iconCacheByExePathLower[$exePathLower]=$extractedIconBase64
            }
            $iconBase64=$iconCacheByExePathLower[$exePathLower]
        }
        if(-not $iconBase64){ $iconBase64=$defaultIconBase64 }
        $targetItem.IconBase64=$iconBase64
    }
}

function Get-UserSessionWindow {
    <#
    Purpose : Collect the windows matching the title queries in every reachable user session.
    - As SYSTEM, one helper per active user session is started concurrently, then all of them are awaited against one shared deadline.
    - As an interactive administrator, only the windows of the current session can be enumerated.
    Returns an array of @{ SessionId; ProcessId; Title; ExePath; Name; IconBase64 }
    #>
    param([hashtable]$SearchCriteria,[hashtable]$SessionContext)
    $windowEntries=@()
    $queryLiterals=@()
    foreach($titleQuery in $SearchCriteria.TitleQueries){ $queryLiterals+=("@{ TitlePattern=" + (Format-SingleQuotedLiteral $titleQuery.TitlePatternLower) + "; ProcessNamePattern=" + (Format-SingleQuotedLiteral $titleQuery.ProcNamePatternLower) + " }") }
    $helperScriptText=('$HelperLogEnabled = $' + $script:IsTestMode.ToString().ToLowerInvariant() + "`n" + '$TitleQueries = @(' + ($queryLiterals -join ",") + ")`n" + $script:WindowHelperScriptBody)
    $outputBySession=@()
    if($SessionContext.IsSystem){
        if($SessionContext.ActiveUserSessions.Count -eq 0){ Write-CustomLog "No active user session : window titles cannot be enumerated." }
        $helperLaunches=@()
        foreach($userSession in $SessionContext.ActiveUserSessions){ $helperLaunches+=,(Start-UserSessionScript -SessionId $userSession.SessionId -ScriptText $helperScriptText -ShowWindow:$script:IsTestMode) }
        $helperDeadlineUtc=[DateTime]::UtcNow.AddSeconds(60)
        foreach($helperLaunch in $helperLaunches){
            if(-not $helperLaunch.Success){ continue }
            $helperResult=Wait-UserSessionScript -LaunchContext $helperLaunch -DeadlineUtc $helperDeadlineUtc
            Write-CustomLog ("Window helper of session {0} : TimedOut={1} ExitCode={2} OutputLines={3}" -f $helperLaunch.SessionId,$helperResult.TimedOut,$helperResult.ExitCode,$helperResult.Stdout.Count)
            $outputBySession+=,@{ SessionId=$helperLaunch.SessionId; Lines=$helperResult.Stdout }
        }
    }elseif($SessionContext.IsProcessInteractive){
        $helperResult=Invoke-ScriptInProcess -ScriptText $helperScriptText
        $outputBySession+=,@{ SessionId=$SessionContext.CurrentProcessSessionId; Lines=$helperResult.Stdout }
    }else{
        Write-CustomLog "Window titles cannot be enumerated : the process runs neither as SYSTEM nor inside an interactive session."
    }
    # The helper prints one TSV line per matching window : PID<TAB>Title<TAB>ExePath<TAB>Name<TAB>IconBase64
    foreach($sessionOutput in $outputBySession){
        foreach($outputLine in $sessionOutput.Lines){
            if([string]::IsNullOrEmpty($outputLine)){continue}
            $tsvFields=$outputLine -split "`t",5
            if($tsvFields.Length -lt 5){continue}
            $windowProcessId=0
            if(-not [int]::TryParse($tsvFields[0],[ref]$windowProcessId)){continue}
            $windowEntries+=,@{ SessionId=$sessionOutput.SessionId; ProcessId=$windowProcessId; Title=$tsvFields[1]; ExePath=$tsvFields[2]; Name=$tsvFields[3]; IconBase64=$tsvFields[4] }
        }
    }
    Write-CustomLog ("Matching windows : " + $windowEntries.Count)
    return ,$windowEntries
}


# ==================================================================
#                 WINDOW ENUMERATION SCRIPT (USER SESSION)
# ==================================================================

# Static body of the script that enumerates windows inside a user session. Get-UserSessionWindow prepends the generated
# $HelperLogEnabled and $TitleQueries definitions. Output : one TSV line per matching window (PID, Title, ExePath, Name, IconBase64)
$script:WindowHelperScriptBody = @'
Add-Type -AssemblyName System.Drawing
function Write-HelperLog([string]$Message){
    # The diagnostic log lives in the temp folder of the session user, which is always writable from that session
    if ($HelperLogEnabled) {
        try{
            $timestamp=(Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff")
            Add-Content -LiteralPath (Join-Path ([IO.Path]::GetTempPath()) "CloseProcessPopup_WindowHelper.log") -Value "$timestamp $Message" -Encoding UTF8
        }catch{}
    }
}
Write-HelperLog "=== Helper started ==="
Write-HelperLog ("LanguageMode=" + $ExecutionContext.SessionState.LanguageMode)
Write-HelperLog ("CLR=" + [System.Environment]::Version + "  PS=" + $PSVersionTable.PSVersion)
Write-HelperLog ("ApartmentState=" + [Threading.Thread]::CurrentThread.ApartmentState)
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    try {
        [Threading.Thread]::CurrentThread.TrySetApartmentState([Threading.ApartmentState]::STA) | Out-Null
        Write-HelperLog "Forced ApartmentState=STA"
    } catch {
        Write-HelperLog ("Failed to set STA : " + $_.Exception.Message)
    }
}

# --- Win32 interop (only what is needed for window enumeration) ---
# The types are only compiled once per process, the helper can run several times inside the same PowerShell host
if (-not ('Win32Api2' -as [type])) {
Add-Type @"
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
"@ -ErrorAction Stop
}

# --- Shell COM interop (minimal, turns an AUMID into its icon) ---
$ShellInteropReady = $false
try{
    if (-not ('ShellInterop' -as [type])) {
    Add-Type -ReferencedAssemblies 'System.Drawing' @"
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
"@ -ErrorAction Stop
    }
    $null = [ShellInterop]
    $ShellInteropReady = $true
    Write-HelperLog "ShellInterop loaded OK."
}
catch{
    $ShellInteropReady = $false
    Write-HelperLog ("Add-Type(ShellInterop) FAILED : " + $_.Exception.ToString())
}

function Format-TsvText([string]$Text){ if(-not $Text){return ""}; ($Text -replace "[`t`r`n]"," ") }

function Convert-FuzzyTitle([string]$RawTitle){
    # Normalizes exotic spaces, zero-width characters and typographic dashes, so a pattern typed on a keyboard matches what the application displays
    if(-not $RawTitle){ return "" }
    $normalizedTitle = $RawTitle
    foreach($spaceCodePoint in @(0x00A0,0x1680,0x2000,0x2001,0x2002,0x2003,0x2004,0x2005,0x2006,0x2007,0x2008,0x2009,0x200A,0x202F,0x205F,0x3000)){ $normalizedTitle = $normalizedTitle.Replace([string][char]$spaceCodePoint,' ') }
    foreach($zeroWidthCodePoint in @(0x200B,0x200C,0x200D,0xFEFF)){ $normalizedTitle = $normalizedTitle.Replace([string][char]$zeroWidthCodePoint,'') }
    foreach($dashCodePoint in @(0x2010,0x2011,0x2012,0x2013,0x2014,0x2015,0x2212)){ $normalizedTitle = $normalizedTitle.Replace([string][char]$dashCodePoint,'-') }
    $normalizedTitle = ($normalizedTitle -replace "[`t`r`n]+"," ") -replace " {2,}"," "
    return $normalizedTitle.Trim()
}

function Get-ExePath([int]$processId){
    try{
        $runningProcess = Get-Process -Id $processId -ErrorAction Stop
        if($runningProcess -and $runningProcess.Path){ return $runningProcess.Path }
    }catch{}
    $processHandle=[IntPtr]::Zero
    try{
        $access = [enum]::ToObject([K32+Access],0x1000) # PROCESS_QUERY_LIMITED_INFORMATION
        $processHandle=[K32]::OpenProcess($access,$false,$processId)
        if($processHandle -ne [IntPtr]::Zero){
            $pathBuilder=New-Object System.Text.StringBuilder 1024; $lenRef=$pathBuilder.Capacity
            if([K32]::QueryFullProcessImageName($processHandle,0,$pathBuilder,[ref]$lenRef)){ return $pathBuilder.ToString() }
        }
    }catch{} finally{ if($processHandle -ne [IntPtr]::Zero){ [K32]::CloseHandle($processHandle) | Out-Null } }
    $processHandle=[IntPtr]::Zero
    try{
        $processHandle=[K32]::OpenProcess([K32+Access]::QI -bor [K32+Access]::VMREAD,$false,$processId)
        if($processHandle -ne [IntPtr]::Zero){
            $pathBuilder=New-Object System.Text.StringBuilder 1024; $lenRef=$pathBuilder.Capacity
            if([K32]::QueryFullProcessImageName($processHandle,0,$pathBuilder,[ref]$lenRef)){ return $pathBuilder.ToString() }
        }
    }catch{} finally{ if($processHandle -ne [IntPtr]::Zero){ [K32]::CloseHandle($processHandle) | Out-Null } }
    try{
        $wmiProcess = Get-WmiObject -Class Win32_Process -Filter "ProcessId=$processId" -ErrorAction SilentlyContinue
        if($wmiProcess -and $wmiProcess.ExecutablePath){ return $wmiProcess.ExecutablePath }
    }catch{}
    return $null
}

# Derive AUMID from a WindowsApps path by reading AppxManifest.xml
function Get-AumidFromWindowsAppsPath([string]$exePath){
    try{
        if(-not $exePath -or ($exePath -notlike "*\WindowsApps\*")){ return $null }
        $packageRoot = Split-Path -Parent $exePath
        for($parentLevel=0; $parentLevel -lt 4 -and -not (Test-Path (Join-Path $packageRoot "AppxManifest.xml")); $parentLevel++){
            $packageRoot = Split-Path -Parent $packageRoot
        }
        $manifestPath = Join-Path $packageRoot "AppxManifest.xml"
        if(-not (Test-Path $manifestPath)){ Write-HelperLog "Get-Aumid : no manifest"; return $null }
        $leafFolder = Split-Path -Leaf $packageRoot
        $regexMatch = [regex]::Match($leafFolder,'^(?<name>[^_]+)_[^_]+_[^_]+__?(?<pubid>[^\\]+)$')
        if(-not $regexMatch.Success){ Write-HelperLog ("Get-Aumid : regex miss on '{0}'" -f $leafFolder); return $null }
        $packageFamily = $regexMatch.Groups['name'].Value + "_" + $regexMatch.Groups['pubid'].Value
        [xml]$manifestXml = Get-Content -LiteralPath $manifestPath -Encoding UTF8
        # A package can declare several applications, the first one carries the main entry point
        $applicationNode = @($manifestXml.Package.Applications.Application)[0]
        if(-not $applicationNode){ Write-HelperLog "Get-Aumid : no <Application>"; return $null }
        $appId = [string]$applicationNode.Id
        if(-not $appId){ Write-HelperLog "Get-Aumid : empty AppId"; return $null }
        $packageFamily + "!" + $appId
    }catch{
        Write-HelperLog ("Get-Aumid EX : " + $_.Exception.Message)
        $null
    }
}

function Convert-BitmapToBase64Png([System.Drawing.Bitmap]$bitmap){
    if(-not $bitmap){ return "" }
    $memStream = New-Object System.IO.MemoryStream
    try{
        $bitmap.Save($memStream,[System.Drawing.Imaging.ImageFormat]::Png)
        [Convert]::ToBase64String($memStream.ToArray())
    }catch{ "" }finally{
        try{$memStream.Dispose()}catch{}
        try{$bitmap.Dispose()}catch{}
    }
}

function Get-IconBitmapFromHwnd([IntPtr]$hWnd,[string]$exePath,[int]$reqSize=96){
<#
Priority:
  1) AUMID from WindowsApps path, then ShellInterop.GetIconFromAumid
  2) ExtractAssociatedIcon(exePath)
Fallback: SystemIcons.Application.
#>
    function Invoke-SafeStep([scriptblock]$StepScript,[string]$StepName){
        try{& $StepScript}catch{Write-HelperLog "[$StepName] EX : $($_.Exception.Message)";$null}
    }
    if($ShellInteropReady){
        if($exePath -and $exePath -like "*\WindowsApps\*"){
            $aumidFromPath=Invoke-SafeStep { Get-AumidFromWindowsAppsPath $exePath } 'AUMID.FromPath'
            if($aumidFromPath){
                $iconBitmap=Invoke-SafeStep { [ShellInterop]::GetIconFromAumid($aumidFromPath,$reqSize) } 'ShellInterop.GetIconFromAumid(Path)'
                if($iconBitmap){ Write-HelperLog "[AUMID(Path)] OK"; return $iconBitmap } else { Write-HelperLog "[AUMID(Path)] NULL" }
            } else { Write-HelperLog "[AUMID(Path)] NotFound" }
        }
    } else { Write-HelperLog "[ShellInterop] NotAvailable" }
    if($exePath){
        $iconObj=Invoke-SafeStep { [System.Drawing.Icon]::ExtractAssociatedIcon($exePath) } 'ExtractAssociatedIcon'
        if($iconObj){
            $bitmap=Invoke-SafeStep { $iconObj.ToBitmap() } 'Icon.ToBitmap'
            if($bitmap){ Write-HelperLog "[ExtractAssociatedIcon] OK"; return $bitmap } else { Write-HelperLog "[ExtractAssociatedIcon] NULL.Bmp" }
        } else { Write-HelperLog "[ExtractAssociatedIcon] NULL.Icon" }
    } else { Write-HelperLog "[ExtractAssociatedIcon] No exePath" }
    Write-HelperLog "[Fallback] SystemIcons.Application"
    [System.Drawing.SystemIcons]::Application.ToBitmap()
}

# Enumerate the visible titled windows of the current desktop
$windowList = New-Object System.Collections.ArrayList
[Win32Api2]::EnumWindows({ param($windowHandle,$unused)
    if(-not [Win32Api2]::IsWindowVisible($windowHandle)){ return $true }
    $titleLength=[Win32Api2]::GetWindowTextLength($windowHandle)
    if($titleLength -le 0){ return $true }
    $titleBuilder=New-Object System.Text.StringBuilder ($titleLength+1)
    if([Win32Api2]::GetWindowText($windowHandle,$titleBuilder,$titleBuilder.Capacity) -eq 0){ return $true }
    $title=$titleBuilder.ToString()
    if(-not $title -or $title -match '^\s*$'){ return $true }
    $null = $windowList.Add(@{ Handle=$windowHandle; Title=$title })
    return $true
}, [IntPtr]::Zero) | Out-Null
Write-HelperLog ("Enumerated " + $windowList.Count + " windows")

# Emit one TSV line per window matching a title query : PID<TAB>Title<TAB>ExePath<TAB>Name<TAB>IconBase64
# Matching happens here so that icons are only extracted for the requested windows
foreach($windowEntry in $windowList){
    $processId = 0; [void][Win32Api2]::GetWindowThreadProcessId($windowEntry.Handle,[ref]$processId)
    if($processId -le 0){ continue }
    $normalizedTitle = Convert-FuzzyTitle $windowEntry.Title
    if(-not $normalizedTitle){ $normalizedTitle = $windowEntry.Title }
    $exePath = Get-ExePath $processId
    $processNameOut = ""
    if($exePath){ $processNameOut = [IO.Path]::GetFileName($exePath) }
    else{
        try{
            $windowProcess = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if($windowProcess){ $processNameOut = ($windowProcess.ProcessName + ".exe") }
        }catch{}
    }
    if(-not $processNameOut){ $processNameOut = "unknown.exe" }
    $isRequested = $false
    foreach($titleQuery in $TitleQueries){
        if($normalizedTitle -notlike $titleQuery.TitlePattern){ continue }
        if($titleQuery.ProcessNamePattern -and ($processNameOut -notlike $titleQuery.ProcessNamePattern)){ continue }
        $isRequested = $true
        break
    }
    Write-HelperLog ("Window '{0}' PID={1} Path={2} Requested={3}" -f $normalizedTitle, $processId, ($(if ($exePath) { $exePath } else { "<null>" })), $isRequested)
    if(-not $isRequested){ continue }
    $iconBitmap = Get-IconBitmapFromHwnd $windowEntry.Handle $exePath 32
    $iconBase64 = Convert-BitmapToBase64Png $iconBitmap
    if($iconBase64.Length -gt 0){ Write-HelperLog (" -> Icon Base64 length=" + $iconBase64.Length) } else { Write-HelperLog " -> Icon Base64 EMPTY" }
    $iconOut = if($iconBase64){ ($iconBase64 -replace "`r|`n","") } else { "" }
    [Console]::Out.WriteLine(([string]$processId) + "`t" + (Format-TsvText $normalizedTitle) + "`t" + (Format-TsvText $exePath) + "`t" + (Format-TsvText $processNameOut) + "`t" + $iconOut)
}

Write-HelperLog "=== Helper end ==="
'@

# ==================================================================
#                           SCRIPT STARTERS
# ==================================================================

function Split-OutputLine([string]$OutputText) {
    # Returns the lines of a captured output as an array, an empty text gives an empty array
    if ([string]::IsNullOrEmpty($OutputText)) { return ,@() }
    return ,@($OutputText -split "`r?`n")
}

function Invoke-ScriptInProcess {
    <#
    Purpose : Run the provided script text inside the current PowerShell process, which is how an interactive administrator reaches his own session.
    Everything the script writes to [Console]::Out is captured and returned line by line.
    Returns : @{ Success=[bool]; ProcessId=[int]; Error=[string|null]; Stdout=[string[]]; Stderr=[string[]] }
    #>
    param([Parameter(Mandatory=$true)][string]$ScriptText)
    Write-CustomLog "Invoke-ScriptInProcess : compiling script"
    $compiledScript=$null
    try   { $compiledScript=[ScriptBlock]::Create($ScriptText) }
    catch {
        Write-CustomLog ("Invoke-ScriptInProcess : compile error : " + $_.Exception.Message)
        return @{ Success=$false; ProcessId=$PID; Error=("Script compile error : " + $_.Exception.Message); Stdout=@(); Stderr=@() }
    }
    $previousConsoleOut=[Console]::Out
    $capturedOutput=New-Object IO.StringWriter
    [Console]::SetOut($capturedOutput)
    $previousErrorActionPreference=$ErrorActionPreference
    try{
        $ErrorActionPreference='Stop'
        & $compiledScript | Out-Null
        $capturedLines=Split-OutputLine $capturedOutput.ToString()
        Write-CustomLog ("Invoke-ScriptInProcess : completed, output lines=" + $capturedLines.Count)
        return @{ Success=$true; ProcessId=$PID; Error=$null; Stdout=$capturedLines; Stderr=@() }
    }catch{
        $capturedLines=Split-OutputLine $capturedOutput.ToString()
        $failurePosition=""
        if($_.InvocationInfo){ $failurePosition=[string]$_.InvocationInfo.PositionMessage }
        Write-CustomLog ("Invoke-ScriptInProcess : runtime error : " + $_.Exception.Message)
        return @{ Success=$false; ProcessId=$PID; Error=("Runtime error : " + $_.Exception.Message); Stdout=$capturedLines; Stderr=@($failurePosition) }
    }finally{
        try{ [Console]::SetOut($previousConsoleOut) }catch{}
        try{ $capturedOutput.Dispose() }catch{}
        $ErrorActionPreference=$previousErrorActionPreference
    }
}

function Start-PipeReader {
    <#
    Purpose : Drain one redirected pipe of a child process from a background runspace, line by line (UTF-8 without BOM), until EOF.
    With -LogLines every line is also appended to the log as soon as it arrives, which is how a child running in a user session gets its messages recorded.
    Without it the lines are only collected, which suits bulky machine-readable output.
    Returns : @{ Runspace; PowerShell; AsyncResult; Lines (synchronized ArrayList); IsCompleted }
    #>
    param([string]$ReaderName,[System.IO.FileStream]$FileStream,[switch]$LogLines)
    $collectedLines=[System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $readerRunspace=[System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace(); $readerRunspace.Open()
    $readerRunspace.SessionStateProxy.SetVariable('PipeStream',$FileStream)
    $readerRunspace.SessionStateProxy.SetVariable('CollectedLines',$collectedLines)
    $readerRunspace.SessionStateProxy.SetVariable('ReaderName',$ReaderName)
    $readerRunspace.SessionStateProxy.SetVariable('LogEachLine',[bool]$LogLines)
    $readerRunspace.SessionStateProxy.SetVariable('ProgressInterval',200)
    $readerRunspace.SessionStateProxy.SetVariable('LogPath',$script:LogPath)
    $readerRunspace.SessionStateProxy.SetVariable('LogMutex',$script:LogMutex)
    $readerPowerShell=[System.Management.Automation.PowerShell]::Create(); $readerPowerShell.Runspace=$readerRunspace
    [void]$readerPowerShell.AddScript({
        # A fresh runspace does not inherit functions from the caller scope, so a minimal file logger is defined locally
        # The shared mutex serializes its writes against the main thread and the other readers
        # An abandoned mutex still grants ownership to the caller, so the exception is treated as a successful acquisition
        function Write-ReaderLog([string]$Message){
            $timestamp=Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
            $mutexAcquired=$false
            $streamWriter=$null
            try{
                if($LogMutex){ try{ $mutexAcquired=$LogMutex.WaitOne(3000) }catch [System.Threading.AbandonedMutexException]{ $mutexAcquired=$true } }
                $streamWriter=New-Object IO.StreamWriter($LogPath,$true,[Text.Encoding]::UTF8)
                $streamWriter.WriteLine("$timestamp - $Message")
            }catch{}finally{
                if($streamWriter){ $streamWriter.Close() }
                if($mutexAcquired){ try{ $LogMutex.ReleaseMutex() }catch{} }
            }
        }
        $streamReader=$null; $drainedLineCount=0; $startTickCount=[Environment]::TickCount
        try{
            $streamReader=New-Object System.IO.StreamReader($PipeStream,(New-Object System.Text.UTF8Encoding($false)),$true,4096)
            $currentLine=$null
            while($null -ne ($currentLine=$streamReader.ReadLine())){
                [void]$CollectedLines.Add($currentLine); $drainedLineCount++
                if($LogEachLine){ Write-ReaderLog ("[" + $ReaderName + "] " + $currentLine) }
                elseif(($drainedLineCount%$ProgressInterval)-eq 0){ Write-ReaderLog ("[Reader {0}] Drained {1} lines (elapsed {2} ms)" -f $ReaderName,$drainedLineCount,([Environment]::TickCount-$startTickCount)) }
            }
            Write-ReaderLog ("[Reader {0}] EOF. TotalLines={1}" -f $ReaderName,$drainedLineCount)
        } catch { Write-ReaderLog ("[Reader {0}] Loop failed : {1}" -f $ReaderName,$_.Exception.Message) }
        finally { try{ if($streamReader){ $streamReader.Dispose() } }catch{} }
    })
    $asyncResult=$readerPowerShell.BeginInvoke()
    return @{ Runspace=$readerRunspace; PowerShell=$readerPowerShell; AsyncResult=$asyncResult; Lines=$collectedLines; IsCompleted=$false }
}

function Complete-PipeReader([hashtable]$PipeReader) {
    # Ends a reader that reached EOF. A reader still blocked after the grace period is abandoned instead of awaited,
    # because a pipe kept open by an unrelated process would otherwise block the backend forever
    if(-not $PipeReader -or $PipeReader.IsCompleted){ return }
    $PipeReader.IsCompleted=$true
    $hasReachedEnd=$false
    try{ $hasReachedEnd=$PipeReader.AsyncResult.AsyncWaitHandle.WaitOne(5000) }catch{}
    if(-not $hasReachedEnd){
        Write-CustomLog "WARNING : a pipe reader did not reach EOF, it is abandoned"
        try{ [void]$PipeReader.PowerShell.BeginStop($null,$null) }catch{}
        return
    }
    try{ [void]$PipeReader.PowerShell.EndInvoke($PipeReader.AsyncResult) }catch{}
    try{ $PipeReader.PowerShell.Dispose() }catch{}
    try{ $PipeReader.Runspace.Close() }catch{}
}

function Close-LaunchContext {
    # Single place releasing everything Start-UserSessionScript created : child process, pipe readers and native handles
    param([hashtable]$LaunchContext,[switch]$TerminateProcess)
    if(-not $LaunchContext){ return }
    if($TerminateProcess -and $LaunchContext.ProcessHandle -ne [IntPtr]::Zero){ try{ [void][Win32Api]::TerminateProcess($LaunchContext.ProcessHandle,3) }catch{} }
    Complete-PipeReader $LaunchContext.StdoutReader
    Complete-PipeReader $LaunchContext.StderrReader
    Close-NativeHandle @($LaunchContext.StdoutReadHandle,$LaunchContext.StderrReadHandle,$LaunchContext.ProcessHandle)
    $LaunchContext.StdoutReadHandle=[IntPtr]::Zero; $LaunchContext.StderrReadHandle=[IntPtr]::Zero; $LaunchContext.ProcessHandle=[IntPtr]::Zero
}

function Start-UserSessionScript {
    <#
    Purpose : As SYSTEM, start PowerShell inside the session of a logged-on user, feed it the script through STDIN and start draining its STDOUT/STDERR.
    The call returns as soon as the child is running, so several sessions can be served concurrently ; Wait-UserSessionScript collects the outcome.
    Returns : @{ Success=[bool]; Error=[string|null]; SessionId; ProcessId; ProcessHandle; StdoutReadHandle; StderrReadHandle; StdoutReader; StderrReader }
    #>
    param(
        [Parameter(Mandatory=$true)][int]$SessionId,
        [Parameter(Mandatory=$true)][string]$ScriptText,
        [Parameter(Mandatory=$false)][switch]$ShowWindow,
        [Parameter(Mandatory=$false)][switch]$LogOutputLines   # records every STDOUT line in the log as it arrives
    )
    $launchContext=@{ Success=$false; Error=$null; SessionId=$SessionId; ProcessId=$null; ProcessHandle=[IntPtr]::Zero; StdoutReadHandle=[IntPtr]::Zero; StderrReadHandle=[IntPtr]::Zero; StdoutReader=$null; StderrReader=$null }
    $powerShellPath=$script:PowerShellPath
    $workingDirectory=Split-Path -Path $powerShellPath -Parent
    $userTokenHandle=[IntPtr]::Zero; $primaryTokenHandle=[IntPtr]::Zero; $environmentBlock=[IntPtr]::Zero
    $stdinReadHandle=[IntPtr]::Zero;  $stdinWriteHandle=[IntPtr]::Zero
    $stdoutReadHandle=[IntPtr]::Zero; $stdoutWriteHandle=[IntPtr]::Zero
    $stderrReadHandle=[IntPtr]::Zero; $stderrWriteHandle=[IntPtr]::Zero
    Write-CustomLog ("Start-UserSessionScript : SessionId={0} PowerShell='{1}' ShowWindow={2}" -f $SessionId,$powerShellPath,[bool]$ShowWindow)
    try{
        # PowerShell 5 reads the whole script from STDIN and runs it as one script block. Older hosts read STDIN statement by statement,
        # with the console code page, so they receive an ASCII-only script
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $bootstrapCommand='[Console]::InputEncoding=[Text.Encoding]::UTF8; $stdinScript=[ScriptBlock]::Create([Console]::In.ReadToEnd()); & $stdinScript'
            $argumentLine="-NoLogo -NoProfile -Sta -ExecutionPolicy Bypass -Command ""$bootstrapCommand"""
            $scriptToSend=$ScriptText
        } else {
            # -creplace keeps the letter case : the case-insensitive operator would turn every uppercase accented letter into a lowercase one
            $scriptToSend=$ScriptText
            $accentMap=@(
                @('à','a'),@('â','a'),@('ä','a'),@('é','e'),@('è','e'),@('ê','e'),@('ë','e'),@('î','i'),@('ï','i'),@('ô','o'),@('ö','o'),@('ù','u'),@('û','u'),@('ü','u'),@('ç','c'),
                @('À','A'),@('Â','A'),@('Ä','A'),@('É','E'),@('È','E'),@('Ê','E'),@('Ë','E'),@('Î','I'),@('Ï','I'),@('Ô','O'),@('Ö','O'),@('Ù','U'),@('Û','U'),@('Ü','U'),@('Ç','C')
            )
            foreach ($accentPair in $accentMap) { $scriptToSend=$scriptToSend -creplace [Regex]::Escape($accentPair[0]), $accentPair[1] }
            $argumentLine='-NoLogo -NoProfile -Sta -ExecutionPolicy Bypass -'
        }
        # The command line starts with the quoted executable path, as every program expects its own name in the first argument
        $commandLine='"' + $powerShellPath + '" ' + $argumentLine
        # CreateProcessAsUser requires these two privileges, which SYSTEM holds but does not always have enabled
        [void](Enable-Privilege "SeIncreaseQuotaPrivilege")
        [void](Enable-Privilege "SeAssignPrimaryTokenPrivilege")
        # Primary token of the user logged on the target session
        if(-not [WtsApi32]::WTSQueryUserToken($SessionId,[ref]$userTokenHandle)){
            $launchContext.Error=("WTSQueryUserToken failed (SessionId={0}, error={1})" -f $SessionId,[Runtime.InteropServices.Marshal]::GetLastWin32Error())
            return $launchContext
        }
        $TOKEN_ALL_ACCESS=0xF01FF; $SECURITY_IMPERSONATION=2; $TOKEN_TYPE_PRIMARY=1
        if(-not [AdvApi32]::DuplicateTokenEx($userTokenHandle,$TOKEN_ALL_ACCESS,[IntPtr]::Zero,$SECURITY_IMPERSONATION,$TOKEN_TYPE_PRIMARY,[ref]$primaryTokenHandle)){
            $launchContext.Error=("DuplicateTokenEx failed (error={0})" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
            return $launchContext
        }
        # The child receives the environment of the user (TEMP, APPDATA, USERPROFILE...) instead of inheriting the one of SYSTEM
        if(-not [Win32Api]::CreateEnvironmentBlock([ref]$environmentBlock,$primaryTokenHandle,$false)){
            $environmentBlock=[IntPtr]::Zero
            Write-CustomLog ("Start-UserSessionScript : CreateEnvironmentBlock failed (error={0}), the child inherits the environment of this process" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        # Three anonymous pipes for the child's STDIN/STDOUT/STDERR ; the ends kept by this process are not inheritable
        $securityAttributes=New-Object Win32Api+SECURITY_ATTRIBUTES
        $securityAttributes.nLength=[Runtime.InteropServices.Marshal]::SizeOf([type]([Win32Api+SECURITY_ATTRIBUTES])); $securityAttributes.bInheritHandle=$true
        if(-not [Win32Api]::CreatePipe([ref]$stdinReadHandle,[ref]$stdinWriteHandle,[ref]$securityAttributes,0)){ $launchContext.Error="CreatePipe(STDIN) failed"; return $launchContext }
        [void][Win32Api]::SetHandleInformation($stdinWriteHandle,[Win32Api]::HANDLE_FLAG_INHERIT,0)
        if(-not [Win32Api]::CreatePipe([ref]$stdoutReadHandle,[ref]$stdoutWriteHandle,[ref]$securityAttributes,0)){ $launchContext.Error="CreatePipe(STDOUT) failed"; return $launchContext }
        [void][Win32Api]::SetHandleInformation($stdoutReadHandle,[Win32Api]::HANDLE_FLAG_INHERIT,0)
        if(-not [Win32Api]::CreatePipe([ref]$stderrReadHandle,[ref]$stderrWriteHandle,[ref]$securityAttributes,0)){ $launchContext.Error="CreatePipe(STDERR) failed"; return $launchContext }
        [void][Win32Api]::SetHandleInformation($stderrReadHandle,[Win32Api]::HANDLE_FLAG_INHERIT,0)
        $launchContext.StdoutReadHandle=$stdoutReadHandle; $launchContext.StderrReadHandle=$stderrReadHandle
        # STARTUPINFO : redirected standard handles (0x100) on the interactive desktop of the session
        $startupInfo=New-Object STARTUPINFO
        $startupInfo.cb=[Runtime.InteropServices.Marshal]::SizeOf([type]([STARTUPINFO]))
        $startupInfo.lpDesktop='winsta0\default'
        $startupInfo.dwFlags=0x100
        $startupInfo.hStdInput=$stdinReadHandle
        $startupInfo.hStdOutput=$stdoutWriteHandle
        $startupInfo.hStdError=$stderrWriteHandle
        if($ShowWindow){ $startupInfo.dwFlags=$startupInfo.dwFlags -bor 0x1; $startupInfo.wShowWindow=1 }
        $CREATE_NO_WINDOW=0x08000000; $CREATE_NEW_CONSOLE=0x00000010; $CREATE_BREAKAWAY_FROM_JOB=0x01000000; $CREATE_UNICODE_ENVIRONMENT=0x00000400
        $creationFlags=$CREATE_NO_WINDOW
        if($ShowWindow){ $creationFlags=$CREATE_NEW_CONSOLE }
        if($environmentBlock -ne [IntPtr]::Zero){ $creationFlags=$creationFlags -bor $CREATE_UNICODE_ENVIRONMENT }
        # Breaking away from the job of the caller keeps the child alive when a deployment tool closes its job. A job that forbids
        # breakaway makes the call fail with ERROR_ACCESS_DENIED (5), in which case the child is created inside the job
        $processInformation=New-Object PROCESS_INFORMATION
        $isProcessCreated=[AdvApi32]::CreateProcessAsUser($primaryTokenHandle,$powerShellPath,$commandLine,[IntPtr]::Zero,[IntPtr]::Zero,$true,[uint32]($creationFlags -bor $CREATE_BREAKAWAY_FROM_JOB),$environmentBlock,$workingDirectory,[ref]$startupInfo,[ref]$processInformation)
        $creationError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if(-not $isProcessCreated -and $creationError -eq 5){
            Write-CustomLog "Start-UserSessionScript : job breakaway denied, creating the child inside the current job"
            $isProcessCreated=[AdvApi32]::CreateProcessAsUser($primaryTokenHandle,$powerShellPath,$commandLine,[IntPtr]::Zero,[IntPtr]::Zero,$true,[uint32]$creationFlags,$environmentBlock,$workingDirectory,[ref]$startupInfo,[ref]$processInformation)
            $creationError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }
        if(-not $isProcessCreated){ $launchContext.Error=("CreateProcessAsUser failed (error={0})" -f $creationError); return $launchContext }
        Close-NativeHandle @($processInformation.hThread)
        $launchContext.ProcessHandle=$processInformation.hProcess
        $launchContext.ProcessId=$processInformation.dwProcessId
        Write-CustomLog ("Start-UserSessionScript : child PID={0}" -f $launchContext.ProcessId)
        # The child owns its ends of the pipes : this process must close its copies, otherwise EOF is never signaled on the read ends
        Close-NativeHandle @($stdinReadHandle,$stdoutWriteHandle,$stderrWriteHandle)
        $stdinReadHandle=[IntPtr]::Zero; $stdoutWriteHandle=[IntPtr]::Zero; $stderrWriteHandle=[IntPtr]::Zero
        # The read ends are wrapped without ownership : Close-LaunchContext closes the native handles
        $stdoutFileStream=New-Object System.IO.FileStream((New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($stdoutReadHandle,$false)),[System.IO.FileAccess]::Read,8192,$false)
        $stderrFileStream=New-Object System.IO.FileStream((New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($stderrReadHandle,$false)),[System.IO.FileAccess]::Read,8192,$false)
        $readerNamePrefix=("Session{0}-PID{1}" -f $SessionId,$launchContext.ProcessId)
        $launchContext.StdoutReader=Start-PipeReader -ReaderName ($readerNamePrefix + "-StdOut") -FileStream $stdoutFileStream -LogLines:$LogOutputLines
        # The error stream is always recorded : it is short, and it is the only trace of a child that fails
        $launchContext.StderrReader=Start-PipeReader -ReaderName ($readerNamePrefix + "-StdErr") -FileStream $stderrFileStream -LogLines
        # The script is written as UTF-8 without BOM after an encoding preamble, then closing STDIN signals EOF to the child
        # The write end is wrapped with ownership, so disposing the writer closes the native handle
        $stdinSafeWriteHandle=New-Object Microsoft.Win32.SafeHandles.SafeFileHandle($stdinWriteHandle,$true)
        $stdinWriteHandle=[IntPtr]::Zero
        $stdinStream=New-Object System.IO.FileStream($stdinSafeWriteHandle,[System.IO.FileAccess]::Write,4096,$false)
        $stdinWriter=New-Object System.IO.StreamWriter($stdinStream,(New-Object System.Text.UTF8Encoding($false)))
        try{
            $stdinWriter.NewLine="`n"; $stdinWriter.AutoFlush=$true
            $encodingPreamble=@'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::InputEncoding  = New-Object System.Text.UTF8Encoding($false)
try { $script:__isPSCore = $PSVersionTable.PSEdition -eq 'Core' } catch { $script:__isPSCore = $false }
if (-not $script:__isPSCore) { try { $OutputEncoding = [Console]::OutputEncoding } catch {} }
'@ + "`n"
            $stdinWriter.Write($encodingPreamble)
            $stdinWriter.Write($scriptToSend)
        } finally { $stdinWriter.Dispose() }
        Write-CustomLog ("Start-UserSessionScript : {0} characters written to the child's STDIN, EOF signaled" -f ($encodingPreamble.Length + $scriptToSend.Length))
        $launchContext.Success=$true
        return $launchContext
    } catch {
        $launchContext.Error=("Unexpected failure : " + $_.Exception.Message)
        return $launchContext
    } finally {
        if($environmentBlock -ne [IntPtr]::Zero){ try{ [void][Win32Api]::DestroyEnvironmentBlock($environmentBlock) }catch{} }
        Close-NativeHandle @($userTokenHandle,$primaryTokenHandle,$stdinReadHandle,$stdinWriteHandle,$stdoutWriteHandle,$stderrWriteHandle)
        if(-not $launchContext.Success){
            Write-CustomLog ("Start-UserSessionScript : launch failed in session {0} : {1}" -f $SessionId,$launchContext.Error)
            if($launchContext.StdoutReadHandle -eq [IntPtr]::Zero){ Close-NativeHandle @($stdoutReadHandle,$stderrReadHandle) }
            Close-LaunchContext -LaunchContext $launchContext -TerminateProcess
        }
    }
}

function Wait-UserSessionScript {
    <#
    Purpose : Await a child started by Start-UserSessionScript until both of its output pipes reach EOF, or until the deadline.
    The waits are event based (reader wait handles, then the process handle). A child still running at the deadline is terminated.
    Returns : @{ Success=[bool]; TimedOut=[bool]; ExitCode=[int64|null]; ProcessId; Stdout=[string[]]; Stderr=[string[]] }
    #>
    param([Parameter(Mandatory=$true)][hashtable]$LaunchContext,[Parameter(Mandatory=$true)][DateTime]$DeadlineUtc)
    $hasTimedOut=$false
    foreach($pipeReader in @($LaunchContext.StdoutReader,$LaunchContext.StderrReader)){
        $remainingMilliseconds=[int][Math]::Max(1,[Math]::Min(2147483647,($DeadlineUtc-[DateTime]::UtcNow).TotalMilliseconds))
        try{ if(-not $pipeReader.AsyncResult.AsyncWaitHandle.WaitOne($remainingMilliseconds)){ $hasTimedOut=$true } }catch{ $hasTimedOut=$true }
    }
    if($hasTimedOut){
        Write-CustomLog ("Wait-UserSessionScript : deadline reached for PID {0} (session {1}), terminating it" -f $LaunchContext.ProcessId,$LaunchContext.SessionId)
        try{ [void][Win32Api]::TerminateProcess($LaunchContext.ProcessHandle,3) }catch{}
    }
    Complete-PipeReader $LaunchContext.StdoutReader
    Complete-PipeReader $LaunchContext.StderrReader
    # Pipe EOF can precede the real end of the process, so the process handle is awaited before reading the exit code,
    # otherwise GetExitCodeProcess could return STILL_ACTIVE (259)
    $exitCode=$null; $rawExitCode=0
    try{
        [void][Win32Api]::WaitForSingleObject($LaunchContext.ProcessHandle,10000)
        if([Win32Api]::GetExitCodeProcess($LaunchContext.ProcessHandle,[ref]$rawExitCode) -and $rawExitCode -ne 259){ $exitCode=[int64]$rawExitCode }
    }catch{}
    $stdoutLines=@(); $stderrLines=@()
    try{ $stdoutLines=@($LaunchContext.StdoutReader.Lines.ToArray()) }catch{}
    try{ $stderrLines=@($LaunchContext.StderrReader.Lines.ToArray()) }catch{}
    Close-LaunchContext -LaunchContext $LaunchContext
    Write-CustomLog ("Wait-UserSessionScript : PID {0} ended, TimedOut={1} ExitCode={2} StdOutLines={3} StdErrLines={4}" -f $LaunchContext.ProcessId,$hasTimedOut,$exitCode,$stdoutLines.Count,$stderrLines.Count)
    return @{ Success=((-not $hasTimedOut) -and ($exitCode -eq 0)); TimedOut=$hasTimedOut; ExitCode=$exitCode; ProcessId=$LaunchContext.ProcessId; Stdout=$stdoutLines; Stderr=$stderrLines }
}


# ==================================================================
#                      POPUP SCRIPT (USER SESSION)
# ==================================================================

# Static body of the popup. New-PopupScript prepends the generated definitions of $PopupTitle, $Timer, $PopupRunsInProcess,
# $PopupSignalPrefix, $PopupSignalSuffix and $detectedProcesses
$script:PopupScriptBody = @'
# ----- Optional sidebar logo base64 (rotated 90 degrees to the left) -----
[string]$SidebarLogoBase64 = ""

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

# ------------------------- Logging and backend signals -------------------------
# The popup owns no log file : in-process execution reaches the backend logger directly,
# while a separate process writes to its redirected output stream, which the backend records line by line
function Write-PopupLog([string]$Message) {
    if ($PopupRunsInProcess) { Write-CustomLog ("[Popup] - " + $Message) } else { [Console]::Out.WriteLine("[Popup] - " + $Message) }
}
# The backend only trusts these explicit signals : SHOWN proves that the user saw the popup, RESULT tells how it was closed
function Send-PopupSignal([string]$Signal) { [Console]::Out.WriteLine($PopupSignalPrefix + $Signal + $PopupSignalSuffix) }
# Event handlers run in child scopes, so the mutable state lives in a hashtable that every handler can update
$PopupState = @{ CloseReason=$null; Stopwatch=$null; ExitWatchEnabled=$false; PendingExitCount=0; WatchedProcesses=@(); ExitedHandler=$null }
Write-PopupLog "=== Popup starting ==="

# A failing statement is logged and execution continues, so a cosmetic failure never prevents the popup from being displayed
trap {
    try { Write-PopupLog "UNHANDLED ERROR : $($_.Exception.Message)" } catch {}
    continue
}

function Get-DisplayPrimaryScaling {
    $major = [Environment]::OSVersion.Version.Major
    if ($major -lt 6) {
        try {
            $val = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontDPI' -ErrorAction Stop
            if ($val -and $val.LogPixels -is [int] -and $val.LogPixels -gt 0) {
                return [math]::Round($val.LogPixels / 96.0, 2)
            }
        } catch { return 1.0 }
    }
    else {
        if (-not ('DPIHelper1' -as [type])) {
        Add-Type @"
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
"@ -ReferencedAssemblies System.Drawing.dll
        }
    return [DPIHelper1]::GetScaling()
    }
}
$DPI_Factor = Get-DisplayPrimaryScaling
Write-PopupLog "DPI = $DPI_Factor "

$decodedList = @()
foreach ($item in $detectedProcesses) {
    $iconImage = $null
    if ($item.IconBase64) {
        try {
            $iconBytes   = [Convert]::FromBase64String($item.IconBase64)
            $iconStream  = New-Object System.IO.MemoryStream(, $iconBytes)
            $streamImage = [System.Drawing.Image]::FromStream($iconStream)
            # The image is cloned to a standalone Bitmap so the stream can be disposed safely
            $iconImage = New-Object System.Drawing.Bitmap $streamImage
            $streamImage.Dispose()
            $iconStream.Dispose()
        } catch { $iconImage = $null }
    }
    if (-not $iconImage) {
        try { $iconImage = [System.Drawing.SystemIcons]::Application.ToBitmap() }
        catch { $iconImage = $null }
    }
    $decodedList += ,@{
        Name        = $item.Name
        ExePath     = $item.ExePath
        Description = $item.Description
        ProcessIds  = $item.ProcessIds
        Icon        = $iconImage
    }
}
$detectedProcesses = $decodedList
Write-PopupLog "detectedProcesses built, count=$($detectedProcesses.Count)"

# ----- Native helpers (DPI + regions + drag) -----
if (-not ('Win32Native' -as [type])) {
    Add-Type -ReferencedAssemblies System.Drawing,System.Windows.Forms -TypeDefinition @"
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
public class NoFocusButton : Button { public NoFocusButton(){ this.SetStyle(ControlStyles.Selectable,false);} }
"@
}
Write-PopupLog "Assemblies Loaded"

try { [DPIHelper2]::SetProcessDPIAware() | Out-Null ; Write-PopupLog "DPI Aware set." } 
catch { Write-PopupLog "Cannot set DPI aware on this system." }

# ----- Localization -----
$IsFrenchUI = $false
try { $IsFrenchUI = ([System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName -eq 'fr') } catch { $IsFrenchUI = $false }
$TextResources = @{
    fr = @{ InstallingOf="Installation de "; DefaultInfo="Veuillez sauvegarder votre travail avant de continuer car les applications suivantes seront fermées automatiquement."; CountdownLabel="Compte à rebours avant fermeture automatique"; ActionButton="Fermer les applications et installer"; HourSuffix="h"; MinSuffix="m"; SecSuffix="s" }
    en = @{ InstallingOf="Installing "; DefaultInfo="Please save your work before continuing because the applications below will be closed automatically."; CountdownLabel="Countdown before automatic closing"; ActionButton="Close apps and install"; HourSuffix="h"; MinSuffix="m"; SecSuffix="s" }
}
$Locale = if ($IsFrenchUI) { $TextResources.fr } else { $TextResources.en }

# ----- helpers -----
function New-FontObject([string]$Family,[float]$Size,[System.Drawing.FontStyle]$Style) { New-Object System.Drawing.Font($Family,$Size,$Style,[System.Drawing.GraphicsUnit]::Point) }
function Set-ControlRoundRegion($Control,[int]$Radius) {
    if (-not $Control -or $Control.IsDisposed) { return }
    if ($Control.Width -le 0 -or $Control.Height -le 0) { return }
    try { $regionHandle = [Win32Native]::CreateRoundRectRgn(0,0,$Control.Width,$Control.Height,$Radius,$Radius); [Win32Native]::SetWindowRgn($Control.Handle,$regionHandle,$true) | Out-Null } catch {}
}
function Format-TimeString([int]$TotalSeconds,[Hashtable]$Loc) {
    if ($TotalSeconds -lt 0) { $TotalSeconds = 0 }
    $hours = [int]([math]::Floor($TotalSeconds/3600)); $minutes = [int]([math]::Floor(($TotalSeconds%3600)/60)); $seconds = [int]($TotalSeconds%60)
    if ($hours -gt 0) { return ("{0}{3} {1}{4} {2}{5}" -f $hours,$minutes,$seconds,$Loc.HourSuffix,$Loc.MinSuffix,$Loc.SecSuffix) }
    elseif ($minutes -gt 0) { return ("{0}{2} {1}{3}" -f $minutes,$seconds,$Loc.MinSuffix,$Loc.SecSuffix) }
    else { return ("{0}{1}" -f $seconds,$Loc.SecSuffix) }
}

# ----- Colors, fonts, spacing -----
$ColorBlack          = [System.Drawing.Color]::FromArgb(0,0,0)
$ColorBlue1          = [System.Drawing.Color]::FromArgb(0,80,200)
$ColorBlue2          = [System.Drawing.Color]::FromArgb(0, 80, 250)
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
$MainForm.ClientSize = New-Object System.Drawing.Size(600,284)

# Layout root (sidebar + main area)
$RootLayout = New-Object System.Windows.Forms.TableLayoutPanel
$RootLayout.Dock = 'Fill'; $RootLayout.ColumnCount=2; $RootLayout.RowCount=1
$sidebarWidthPercent = if ($SidebarLogoBase64) {12} else {4}
$null = $RootLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent,$sidebarWidthPercent))) # Left SideBar
$null = $RootLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent,88)))    # Main column
$null = $RootLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent,100)))         # Main row

$SidebarPanel = New-Object System.Windows.Forms.Panel
$SidebarPanel.Dock = 'Fill' ; $SidebarPanel.BackColor = $ColorBlue1
$SidebarPanel.Margin = [System.Windows.Forms.Padding]::Empty           ; $SidebarPanel.Padding = New-Object System.Windows.Forms.Padding(10,0,10,0)
$SidebarPanel.add_MouseEnter({ $SidebarPanel.BackColor = $ColorBlue2 ; $SidebarPanel.Cursor = [System.Windows.Forms.Cursors]::SizeAll })
$SidebarPanel.add_MouseLeave({ $SidebarPanel.BackColor = $ColorBlue1 ; $SidebarPanel.Cursor = [System.Windows.Forms.Cursors]::Default })

$MainPanel = New-Object System.Windows.Forms.Panel
$MainPanel.Dock='Fill'; $MainPanel.BackColor=$ColorMainBackground
$MainPanel.Padding=New-Object System.Windows.Forms.Padding(12,0,12,0)

$RootLayout.Controls.Add($SidebarPanel,0,0)
$RootLayout.Controls.Add($MainPanel,1,0)

# Main content layout
$MainContent = New-Object System.Windows.Forms.TableLayoutPanel
$MainContent.Dock='Fill'; $MainContent.ColumnCount=1; $MainContent.RowCount=5
$null = $MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,63)))  # Title
$null = $MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,155))) # Central zone
$null = $MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,14)))  # Spacer
$null = $MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,28)))  # Button zone
$null = $MainContent.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,12)))  # Spacer
$MainPanel.Controls.Add($MainContent)

# Header label
$HeaderLabel = New-Object System.Windows.Forms.Label
$HeaderLabel.ForeColor = $ColorTextMain
$HeaderLabel.Font = $FontHeader
$HeaderLabel.AutoSize = $false
$HeaderLabel.Dock = 'Fill'
$HeaderLabel.TextAlign = 'MiddleLeft'
function Set-HeaderLabelHeight([System.Windows.Forms.Label]$label,[string]$prefix,[string]$PopupTitle) {
    $maxSize = $label.ClientSize
    if ($maxSize.Width -le 0) { $maxSize = New-Object System.Drawing.Size(580,63) } # fallback
    $stringFormat = New-Object System.Drawing.StringFormat
    $stringFormat.FormatFlags = [System.Drawing.StringFormatFlags]::LineLimit
    $stringFormat.Trimming    = [System.Drawing.StringTrimming]::EllipsisWord
    $graphics = [System.Drawing.Graphics]::FromHwnd($label.Handle)
    try {
        $fullText   = "$prefix$PopupTitle"
        $measured   = $graphics.MeasureString($fullText,$label.Font,$maxSize.Width,$stringFormat)
        $lineHeight = $label.Font.Height
        $threshold  = [math]::Ceiling($lineHeight * 1.5)
        if ($measured.Height -le $threshold) {
            $label.Text = $fullText
            $label.AutoEllipsis = $false
        } else {
            $twoLines = "$prefix`r`n$PopupTitle"
            $label.Text = $twoLines
            $label.AutoEllipsis = $true
            $MainContent.RowStyles[0].Height += 7
            $MainContent.RowStyles[2].Height -= 3
        }
    } finally {
        $graphics.Dispose()
    }
}

# Card with message + process list + status bar
$CardBorderPanel = New-Object System.Windows.Forms.Panel
$CardBorderPanel.Dock='Fill'; $CardBorderPanel.BackColor=$ColorCardBorder; $CardBorderPanel.Padding=New-Object System.Windows.Forms.Padding(1)
$CardPanel = New-Object System.Windows.Forms.Panel
$CardPanel.Dock='Fill'; $CardPanel.BackColor=[System.Drawing.Color]::White; $CardPanel.Padding=New-Object System.Windows.Forms.Padding(16)
$CardBorderPanel.Controls.Add($CardPanel)

$CardLayout = New-Object System.Windows.Forms.TableLayoutPanel
$CardLayout.Dock='Fill'; $CardLayout.ColumnCount=1; $CardLayout.RowCount=3
$null = $CardLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,46))) # Message
$null = $CardLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,28))) # Processes zone
$null = $CardLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute,45))) # Countdown zone
$CardPanel.Controls.Add($CardLayout)

# Info message (auto-wrap by MaximumSize)
$InfoLabel = New-Object System.Windows.Forms.Label
$InfoLabel.AutoSize=$true; $InfoLabel.Font=$FontText; $InfoLabel.ForeColor=$ColorTextMain
$InfoLabel.Text = $Locale.DefaultInfo 
$InfoLabel.Dock='Top'; $InfoLabel.Margin=New-Object System.Windows.Forms.Padding(0,0,0,8)
$CardLayout.Controls.Add($InfoLabel,0,0)
$AdjustInfoWidth = { $infoParent=$InfoLabel.Parent; if ($infoParent -and -not $infoParent.IsDisposed) { $availableWidth=[Math]::Max(100,$infoParent.ClientSize.Width - $InfoLabel.Margin.Left - $InfoLabel.Margin.Right); $InfoLabel.MaximumSize=New-Object System.Drawing.Size($availableWidth,0) } }
& $AdjustInfoWidth

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
$StatusBar.Padding=New-Object System.Windows.Forms.Padding(10,0,10,0); $StatusBar.Margin=New-Object System.Windows.Forms.Padding(0,12,0,0)
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
    if (-not $BaseColor) { $BaseColor = $ColorBlue1 }
    $frameBitmap = New-Object Drawing.Bitmap $Size,$Size
    $frameGraphics = [Drawing.Graphics]::FromImage($frameBitmap); $frameGraphics.SmoothingMode='AntiAlias'
    $pulseColor = [Drawing.Color]::FromArgb([math]::Min([math]::Max([int]$Alpha,0),255),$BaseColor.R,$BaseColor.G,$BaseColor.B)
    $pulseRadius = ($Size/1.2)*$Scale
    $pulseBounds = New-Object Drawing.RectangleF((($Size/2)-$pulseRadius-0.6),(($Size/2)-$pulseRadius-0.6),(2*$pulseRadius),(2*$pulseRadius))
    $pulseBrush = New-Object Drawing.SolidBrush $pulseColor
    $frameGraphics.FillEllipse($pulseBrush,$pulseBounds)
    $pulseBrush.Dispose()
    $frameGraphics.Dispose()
    return $frameBitmap
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
    $previousFrame,$PulsePictureBox.Image = $PulsePictureBox.Image,(New-PulseFrameBitmap $PulseAnim.Size $scale $alpha $baseColor)
    if ($previousFrame) { $previousFrame.Dispose() }
})

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
$CloseButton.add_Click({ Write-PopupLog "User click on Close button" ; $PopupState.CloseReason = 'UserConfirmed' ; $MainForm.Close() })
$CloseButton.TabStop = $false

# Compose main layout sections
$MainContent.Controls.Add($HeaderLabel,0,0)
$MainContent.Controls.Add($CardBorderPanel,0,1)
$MainContent.Controls.Add($CloseButton,0,3)
$MainForm.Controls.Add($RootLayout)

# ----- Per-process item builder -----
function New-ProcessRowPanel($Icon,[string]$DisplayDescription,[string]$ExecutableName) {
    $row = New-Object System.Windows.Forms.TableLayoutPanel
    $row.Width=if ($SidebarLogoBase64) {410} else {459}; $row.Height=$cardHeight; $row.Margin = New-Object System.Windows.Forms.Padding 0,0,0,0
    $row.BackColor=[System.Drawing.Color]::White; $row.ColumnCount=2; $row.RowCount=1
    $null = $row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle ([System.Windows.Forms.SizeType]::Absolute,64))) # Process icon
    $null = $row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle ([System.Windows.Forms.SizeType]::Percent,100))) # Process infos
    $null = $row.RowStyles.Add((New-Object System.Windows.Forms.RowStyle ([System.Windows.Forms.SizeType]::Percent,100))) 
    $iconBox = New-Object System.Windows.Forms.PictureBox
    $iconBox.SizeMode='CenterImage'; $iconBox.Image=$Icon; $iconBox.Dock='Fill'
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

Write-PopupLog "Building UI rows for $($detectedProcesses.Count) processes..."

foreach ($proc in $detectedProcesses) {
    if ($ProcessFlow.Controls.Count -lt 3) {
        $MainForm.Height += $cardHeight
        $CardLayout.RowStyles[1].Height += $cardHeight * $DPI_Factor
        $MainContent.RowStyles[1].Height += $cardHeight * $DPI_Factor
    }
    $itemPanel = New-ProcessRowPanel -Icon $proc.Icon -DisplayDescription $proc.Description -ExecutableName $proc.Name
    $ProcessFlow.Controls.Add($itemPanel) | Out-Null
}

try {
    [byte[]]$logoBytes = [Convert]::FromBase64String($SidebarLogoBase64)
    $logoStream = New-Object System.IO.MemoryStream($logoBytes, $false)
    $logoImage  = [System.Drawing.Image]::FromStream($logoStream, $true, $true)
    $logoBitmap = New-Object System.Drawing.Bitmap($logoImage)
    $logoImage.Dispose(); $logoStream.Dispose()
    $logoBitmap.RotateFlip([System.Drawing.RotateFlipType]::Rotate270FlipNone)
    $logoBox = New-Object TransparentPictureBox
    $logoBox.Dock='Fill'; $logoBox.SizeMode='Zoom'; $logoBox.BackColor=[System.Drawing.Color]::Transparent; $logoBox.Image=$logoBitmap
    [void]$SidebarPanel.Controls.Add($logoBox)
} catch {}

# ----- Initial placement (bottom-right of primary working area) -----
$MainForm.ResumeLayout()
$work = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$MainForm.Location = New-Object System.Drawing.Point([Math]::Max(0,$work.Right-$MainForm.Width),[Math]::Max(0,$work.Bottom-$MainForm.Height))

# ----- Countdown timer (UI update + close at zero) -----
# The remaining time derives from a stopwatch started when the form is shown, so late timer ticks never stretch the countdown
$MainForm.Tag = @{ Remaining=[Math]::Max(0,$Timer); CountdownTimer=(New-Object System.Windows.Forms.Timer) }
$MainForm.Tag.CountdownTimer.Interval = 200
$MainForm.Tag.CountdownTimer.add_Tick({
    $MainForm.Tag['Remaining'] = [int][Math]::Max(0,[Math]::Ceiling($Timer - $PopupState.Stopwatch.Elapsed.TotalSeconds))
    $CountdownValueLabel.Text = Format-TimeString -TotalSeconds $MainForm.Tag['Remaining'] -Loc $Locale
    if ($MainForm.Tag['Remaining'] -lt 60) { $CountdownValueLabel.ForeColor = $ColorRed } else { $CountdownValueLabel.ForeColor = $ColorTextMain }
    if ($MainForm.Tag['Remaining'] -le 0 -and -not $PopupState.CloseReason) { $MainForm.Tag.CountdownTimer.Stop(); $PopupState.CloseReason = 'TimerExpired'; Write-PopupLog "Timer expired, closing form." ; $MainForm.Close() }
})

# ----- Automatic closing once every listed process has exited -----
function Stop-ProcessExitWatch {
    # The handlers are detached before the form disappears : an Exited event raised without a form would run on a thread that has no runspace
    $PopupState.ExitWatchEnabled = $false
    foreach ($watchedProcess in $PopupState.WatchedProcesses) {
        try { $watchedProcess.EnableRaisingEvents = $false } catch {}
        try { if ($PopupState.ExitedHandler) { $watchedProcess.remove_Exited($PopupState.ExitedHandler) } } catch {}
        try { $watchedProcess.Dispose() } catch {}
    }
    $PopupState.WatchedProcesses = @()
}
function Start-ProcessExitWatch {
    # Process.Exited is marshaled through the form (SynchronizingObject), so the handler runs on the UI thread and nothing is polled
    # The watch is only armed when every listed process can be opened from this session, otherwise the countdown and the button remain the only ways out
    $watchedProcessIds = @()
    foreach ($detectedItem in $detectedProcesses) {
        foreach ($listedProcessId in $detectedItem.ProcessIds) { if ($null -ne $listedProcessId -and $watchedProcessIds -notcontains $listedProcessId) { $watchedProcessIds += ,$listedProcessId } }
    }
    if ($watchedProcessIds.Count -eq 0) { return }
    foreach ($watchedProcessId in $watchedProcessIds) {
        try { $PopupState.WatchedProcesses += ,([System.Diagnostics.Process]::GetProcessById([int]$watchedProcessId)) }
        catch {
            # GetProcessById throws ArgumentException for a process that has already exited, which simply counts as exited
            $isAlreadyGone = ($_.Exception -is [ArgumentException]) -or ($_.Exception.InnerException -is [ArgumentException])
            if (-not $isAlreadyGone) { Write-PopupLog ("Exit watch not armed, PID " + $watchedProcessId + " cannot be opened : " + $_.Exception.Message); Stop-ProcessExitWatch; return }
        }
    }
    if ($PopupState.WatchedProcesses.Count -eq 0) { $PopupState.CloseReason = 'ProcessesExited'; Write-PopupLog "Every listed process has already exited, closing form."; $MainForm.Close(); return }
    $PopupState.PendingExitCount = $PopupState.WatchedProcesses.Count
    $PopupState.ExitedHandler = [EventHandler]{
        if (-not $PopupState.ExitWatchEnabled) { return }
        $PopupState.PendingExitCount = $PopupState.PendingExitCount - 1
        if ($PopupState.PendingExitCount -le 0 -and -not $PopupState.CloseReason) { $PopupState.CloseReason = 'ProcessesExited'; Write-PopupLog "Every listed process has exited, closing form."; $MainForm.Close() }
    }
    $PopupState.ExitWatchEnabled = $true
    foreach ($watchedProcess in $PopupState.WatchedProcesses) {
        try {
            $watchedProcess.SynchronizingObject = $MainForm
            $watchedProcess.add_Exited($PopupState.ExitedHandler)
            $watchedProcess.EnableRaisingEvents = $true
        } catch {
            Write-PopupLog ("Exit watch not armed, PID " + $watchedProcess.Id + " cannot be watched : " + $_.Exception.Message)
            Stop-ProcessExitWatch
            return
        }
    }
    Write-PopupLog ("Exit watch armed on " + $PopupState.WatchedProcesses.Count + " processes")
}

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
    $frmBounds = $MainForm.Bounds
    $clampedLeft = [Math]::Max($primary.Left,[Math]::Min($frmBounds.Left,$primary.Right-$frmBounds.Width))
    $clampedTop = [Math]::Max($primary.Top,[Math]::Min($frmBounds.Top,$primary.Bottom-$frmBounds.Height))
    if ($clampedLeft -ne $frmBounds.Left -or $clampedTop -ne $frmBounds.Top -or [System.Windows.Forms.Screen]::FromControl($MainForm) -ne [System.Windows.Forms.Screen]::PrimaryScreen) {
        $MainForm.Location = New-Object Drawing.Point $clampedLeft,$clampedTop
    }
})

$MainForm.add_Shown({ 
    Set-HeaderLabelHeight $HeaderLabel $Locale.InstallingOf $PopupTitle
    Set-ControlRoundRegion $MainForm 20; Set-ControlRoundRegion $CardBorderPanel 12; Set-ControlRoundRegion $CardPanel 10; Set-ControlRoundRegion $ProcessBorderPanel 9; Set-ControlRoundRegion $ProcessScrollPanel 7
    $PopupState.Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $MainForm.Tag.CountdownTimer.Start()
    & $AdjustInfoWidth
    $PulseTimer.Start()
    Send-PopupSignal 'SHOWN'
    Write-PopupLog "Form Shown."
    Start-ProcessExitWatch
})

# Only the button, the countdown and the exit watch may close the popup : Alt+F4 and similar user requests are ignored
$MainForm.add_FormClosing({
    if (-not $PopupState.CloseReason -and $_.CloseReason -eq [System.Windows.Forms.CloseReason]::UserClosing) { $_.Cancel = $true }
})

$MainForm.add_FormClosed({
    try { $MainForm.Tag.CountdownTimer.Stop() } catch {}
    try { Stop-ProcessExitWatch } catch {}
    $closeResult = if ($PopupState.CloseReason) { $PopupState.CloseReason } else { "Aborted-" + $_.CloseReason }
    Write-PopupLog ("Form closed, result=" + $closeResult)
    Send-PopupSignal ("RESULT=" + $closeResult)
    try { if ($PulseTimer) { $PulseTimer.Stop() } } catch {}
    try { if ($PulsePictureBox -and $PulsePictureBox.Image) { $PulsePictureBox.Image.Dispose() } } catch {}
    try {
        if ($ProcessFlow -and $ProcessFlow.Controls) {
            foreach ($row in $ProcessFlow.Controls) {
                try {
                    $rowIconBox = $null
                    if ($row -and $row.Controls -and $row.Controls.Count -gt 0) { $rowIconBox = $row.Controls[0] }
                    if ($rowIconBox -and $rowIconBox.Image) { $rowIconBox.Image.Dispose() }
                } catch {}
            }
        }
    } catch {}
    try { if ($logoBox -and $logoBox.Image) { $logoBox.Image.Dispose() } } catch {}
})

# ----- Message loop, it returns once the form is closed -----
[void][System.Windows.Forms.Application]::Run($MainForm)
'@

function New-PopupScript {
    # Builds the popup script of one session : a generated parameter block followed by the static body
    # Every value goes through Format-SingleQuotedLiteral, so window titles and descriptions can never break out of their literal
    param([string]$PopupTitle,[object[]]$Items,[int]$Timer,[switch]$RunsInProcess)
    $itemLiterals=@()
    foreach($targetItem in $Items){
        $processIdList=(@($targetItem.Targets | ForEach-Object { [int]$_.ProcessId })) -join ","
        $itemLiterals+=("    @{ Name=" + (Format-SingleQuotedLiteral $targetItem.Name) + "; ExePath=" + (Format-SingleQuotedLiteral $targetItem.ExePath) + "; Description=" + (Format-SingleQuotedLiteral $targetItem.Description) + "; IconBase64=" + (Format-SingleQuotedLiteral $targetItem.IconBase64) + "; ProcessIds=@(" + $processIdList + ") }")
    }
    $parameterLines=@(
        ('$PopupTitle = ' + (Format-SingleQuotedLiteral $PopupTitle)),
        ('$Timer = ' + ([int]$Timer).ToString()),
        ('$PopupRunsInProcess = $' + $RunsInProcess.IsPresent.ToString().ToLowerInvariant()),
        ('$PopupSignalPrefix = ' + (Format-SingleQuotedLiteral $script:PopupSignalPrefix)),
        ('$PopupSignalSuffix = ' + (Format-SingleQuotedLiteral $script:PopupSignalSuffix)),
        '$detectedProcesses = @(',
        ($itemLiterals -join ",`n"),
        ')'
    )
    return (($parameterLines -join "`n") + "`n" + $script:PopupScriptBody)
}

function Get-PopupOutcome([object[]]$OutputLines) {
    # Reads the signals written by the popup : SHOWN proves it was displayed, RESULT tells how it was closed
    $popupOutcome=@{ WasShown=$false; Result=$null }
    $signalPattern=[Regex]::Escape($script:PopupSignalPrefix) + '(.+?)' + [Regex]::Escape($script:PopupSignalSuffix)
    foreach($outputLine in $OutputLines){
        if([string]::IsNullOrEmpty($outputLine)){continue}
        if($outputLine -notmatch $signalPattern){continue}
        $signalText=$Matches[1]
        if($signalText -eq 'SHOWN'){ $popupOutcome.WasShown=$true }
        elseif($signalText -like 'RESULT=*'){ $popupOutcome.Result=$signalText.Substring(7) }
    }
    return $popupOutcome
}

function Select-SessionItem {
    # A session is shown the windows it owns, the processes it runs, and the processes that belong to no session receiving a popup
    # (services, disconnected sessions), so every targeted process is announced to at least one user whenever somebody can be warned
    param([object[]]$Items,[int]$SessionId,[hashtable]$ReachableSessionIds)
    $sessionItems=@()
    foreach($targetItem in $Items){
        if(-not $targetItem){continue}
        if($targetItem.Source -eq 'Title'){
            if($targetItem.SessionId -eq $SessionId){ $sessionItems+=,$targetItem }
            continue
        }
        foreach($processTarget in $targetItem.Targets){
            if($processTarget.SessionId -eq $SessionId -or -not $ReachableSessionIds.ContainsKey([int]$processTarget.SessionId)){ $sessionItems+=,$targetItem; break }
        }
    }
    return ,$sessionItems
}


# ==================================================================
#                           CLOSE PROCESSES
# ==================================================================

function Test-TargetAlive([hashtable]$ProcessTarget) {
    # A pinned handle is authoritative : the process object only becomes signaled (WAIT_OBJECT_0) once the process has really terminated
    # Without handle the PID is looked up, which is the best available answer for a process that cannot be opened
    if($ProcessTarget.Handle -ne [IntPtr]::Zero){ return ([Win32Api]::WaitForSingleObject($ProcessTarget.Handle,0) -ne 0) }
    try{ return [bool](Get-WmiObject -Class Win32_Process -Filter ("ProcessId=" + $ProcessTarget.ProcessId) -ErrorAction Stop) }catch{ return $false }
}

function Add-PinnedTarget {
    # Merges the targets of a scan into the dictionary of pinned processes, keyed by PID. The dictionary takes ownership of the handles
    # A PID cannot be recycled while a handle pins it, so a PID that is already pinned designates the same process and its extra handle is released
    param([hashtable]$PinnedTargets,[object[]]$Items,[hashtable]$ReportedCriticalKeys)
    foreach($targetItem in $Items){
        if(-not $targetItem){continue}
        if($targetItem.CriticalReason){
            if(-not $ReportedCriticalKeys.ContainsKey($targetItem.Key)){
                $ReportedCriticalKeys[$targetItem.Key]=$true
                Write-CustomLog ("WARNING : {0} matches the request but is a critical system process, it is left running ({1})" -f $targetItem.Name,$targetItem.CriticalReason)
            }
            Close-TargetItemHandle @($targetItem)
            continue
        }
        foreach($processTarget in $targetItem.Targets){
            $pinnedTarget=$PinnedTargets[$processTarget.ProcessId]
            if($pinnedTarget -and $pinnedTarget.Handle -ne [IntPtr]::Zero){ Close-NativeHandle @($processTarget.Handle) }
            else{ $PinnedTargets[$processTarget.ProcessId]=@{ ProcessId=$processTarget.ProcessId; Handle=$processTarget.Handle; CanTerminate=$processTarget.CanTerminate; Name=$targetItem.Name } }
            $processTarget.Handle=[IntPtr]::Zero
        }
    }
}

function Invoke-TaskkillByProcessId([int[]]$ProcessIds) {
    # Fallback for the processes that could not be opened with the terminate right : taskkill reaches some of them through its own privileges
    if(-not $ProcessIds -or $ProcessIds.Count -eq 0){ return }
    $taskkillPath=Join-Path ([Environment]::SystemDirectory) "taskkill.exe"
    $batchSize=50
    for($startIndex=0; $startIndex -lt $ProcessIds.Count; $startIndex+=$batchSize){
        $taskkillArguments=@('/F')
        foreach($batchProcessId in $ProcessIds[$startIndex..([Math]::Min($startIndex+$batchSize-1,$ProcessIds.Count-1))]){ $taskkillArguments+=@('/PID',([string]$batchProcessId)) }
        try{
            $taskkillOutput=@(& $taskkillPath @taskkillArguments 2>$null)
            if($taskkillOutput.Count -gt 0){ Write-CustomLog ("Taskkill by PID :`n" + ($taskkillOutput -join [Environment]::NewLine)) }
        }catch{ Write-CustomLog ("ERROR : taskkill(/PID) failed : " + $_.Exception.Message) }
    }
}

function Wait-TargetExit {
    # Blocks on the pinned process handles until every process has exited or the shared deadline is reached, without any polling
    param([object[]]$ProcessTargets,[int]$TimeoutMilliseconds)
    $deadlineUtc=[DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    foreach($processTarget in $ProcessTargets){
        if(-not $processTarget -or $processTarget.Handle -eq [IntPtr]::Zero){continue}
        $remainingMilliseconds=[int][Math]::Max(0,($deadlineUtc-[DateTime]::UtcNow).TotalMilliseconds)
        [void][Win32Api]::WaitForSingleObject($processTarget.Handle,[uint32]$remainingMilliseconds)
    }
}

function Stop-TargetProcess {
    <#
    Purpose : Terminate the targeted processes and prove that nothing matching the request is left.
    - Each pass re-scans the system (processes started meanwhile, respawned by a watchdog...), terminates what is alive and waits on the process handles.
    - Success is a pass that finds nothing alive. After -Attempts terminating passes, a last scan decides between success and exit code 15.
    - Only the processes that matched are terminated, through their pinned handles, and their child processes are left alone.
    #>
    param([object[]]$InitialItems,[hashtable]$SearchCriteria,[hashtable]$SessionContext,[hashtable]$ExcludedProcessIds,[int]$Attempts,[bool]$RescanBeforeFirstPass)
    if($Attempts -lt 1){ $Attempts=1 }
    $terminationWaitMilliseconds=5000
    $pinnedTargets=@{}; $reportedCriticalKeys=@{}; $survivingTargets=@()
    Add-PinnedTarget -PinnedTargets $pinnedTargets -Items $InitialItems -ReportedCriticalKeys $reportedCriticalKeys
    $passNumber=0
    while($true){
        $passNumber++
        if($passNumber -gt 1 -or $RescanBeforeFirstPass){
            # Windows are only enumerated again on the first pass : later passes exist for respawning processes, which are caught by name, path or DLL
            $scanResult=Find-TargetProcess -SearchCriteria $SearchCriteria -SessionContext $SessionContext -ExcludedProcessIds $ExcludedProcessIds -SkipTitles:($passNumber -gt 1) -Quiet
            if($null -eq $scanResult){ Write-CustomLog "WARNING : the processes could not be enumerated during this pass, only the already known processes are considered" }
            else{ Add-PinnedTarget -PinnedTargets $pinnedTargets -Items $scanResult.Items -ReportedCriticalKeys $reportedCriticalKeys }
        }
        $aliveTargets=@()
        foreach($pinnedTarget in @($pinnedTargets.Values)){ if(Test-TargetAlive $pinnedTarget){ $aliveTargets+=,$pinnedTarget } }
        if($aliveTargets.Count -eq 0){ break }
        if($passNumber -gt $Attempts){ $survivingTargets=$aliveTargets; break }
        Write-CustomLog ("Pass {0}/{1} : terminating {2} processes : {3}" -f $passNumber,$Attempts,$aliveTargets.Count,((@($aliveTargets | ForEach-Object { $_.Name + "(" + $_.ProcessId + ")" })) -join ", "))
        $taskkillProcessIds=@()
        foreach($aliveTarget in $aliveTargets){
            if(-not $aliveTarget.CanTerminate){ $taskkillProcessIds+=,[int]$aliveTarget.ProcessId; continue }
            if([Win32Api]::TerminateProcess($aliveTarget.Handle,1)){ continue }
            $terminateError=[Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if(Test-TargetAlive $aliveTarget){ Write-CustomLog ("TerminateProcess failed on {0} (PID {1}), error={2}" -f $aliveTarget.Name,$aliveTarget.ProcessId,$terminateError) }
        }
        if($taskkillProcessIds.Count -gt 0){
            Write-CustomLog ("Pass {0}/{1} : {2} processes without terminate right are handed to taskkill" -f $passNumber,$Attempts,$taskkillProcessIds.Count)
            Invoke-TaskkillByProcessId -ProcessIds $taskkillProcessIds
        }
        Wait-TargetExit -ProcessTargets $aliveTargets -TimeoutMilliseconds $terminationWaitMilliseconds
    }
    $survivorsDisplay=(@($survivingTargets | ForEach-Object { $_.Name + "(" + $_.ProcessId + ")" })) -join ", "
    # The pinned handles are released once the verdict is known, which lets the kernel reclaim the process objects
    foreach($pinnedTarget in @($pinnedTargets.Values)){ Close-NativeHandle @($pinnedTarget.Handle); $pinnedTarget.Handle=[IntPtr]::Zero }
    if($survivingTargets.Count -gt 0){
        Write-CustomLog ("ERROR : still running after {0} passes : {1}" -f $Attempts,$survivorsDisplay)
        Stop-Script 15
    }
    Write-CustomLog ("All targeted processes are closed ({0} processes handled, {1} scan passes)" -f $pinnedTargets.Count,$passNumber)
}


# ==================================================================
#                                 MAIN
# ==================================================================

$NoPopup = [string]::IsNullOrEmpty($PopupTitle)
# The popup shows the title exactly as provided, only the log file name needs a sanitized version
$logTitle = "CloseProcessPopup"
if (-not $NoPopup) { $logTitle = Format-Name $PopupTitle }
if ($Timer -lt 1) { $Timer = 600 }
$script:LogPath = Resolve-LogPath -Title $logTitle -CandidateLog $Log
# The mutex exists before any log write so that every writer (main thread, pipe reader runspaces) shares it
$script:LogMutexName = Get-LogMutexName -LogFilePath $script:LogPath
$script:LogMutex = Open-LogMutex -MutexName $script:LogMutexName
Write-CustomLog "========================================="
Write-CustomLog "Starting BACKEND"
Write-CustomLog "========================================="
Write-CustomLog ("Architecture    : process 64-bit=" + $script:ArchitectureContext.IsProcess64Bit + ", OS 64-bit=" + $script:ArchitectureContext.IsOperatingSystem64Bit + ", PROCESSOR_ARCHITECTURE=" + $script:ArchitectureContext.ProcessArchitecture + ", PROCESSOR_ARCHITEW6432=" + $script:ArchitectureContext.Wow64Architecture)
if (-not $script:ArchitectureContext.IsProcess64Bit -and $script:ArchitectureContext.IsOperatingSystem64Bit) { Write-CustomLog "WARNING : 32-bit process on a 64-bit OS, -ProcessDLL cannot see the modules of 64-bit processes" }
# SeDebugPrivilege lets an administrator open the processes of other accounts, which SYSTEM can already do
$isDebugPrivilegeEnabled = Enable-Privilege "SeDebugPrivilege"
$sessionContext = Get-SessionContext
Write-CustomLog ("Current user    : " + $sessionContext.Name)
Write-CustomLog ("Is System       : " + $sessionContext.IsSystem)
Write-CustomLog ("Is Administrator : " + $sessionContext.IsAdmin)
Write-CustomLog ("Debug privilege : " + $isDebugPrivilegeEnabled)
Write-CustomLog ("Own session     : " + $sessionContext.CurrentProcessSessionId + " (interactive=" + $sessionContext.IsProcessInteractive + ")")
if ($sessionContext.ActiveUserSessions.Count -eq 0) { Write-CustomLog "Active sessions : none" }
foreach ($activeUserSession in $sessionContext.ActiveUserSessions) { Write-CustomLog ("Active session  : " + $activeUserSession.SessionId + " (" + $activeUserSession.Station + ") " + $activeUserSession.FullName) }

# --- Detection ---
$searchCriteria = Resolve-SearchCriteria -Processes $Process -ProcessesPaths $ProcessPath -ProcessTitles $ProcessTitle -ProcessDLL $ProcessDLL
# The PowerShell process hosting this script is never a target
$excludedProcessIds = @{}
$excludedProcessIds[[int]$PID] = $true
$initialScan = Find-TargetProcess -SearchCriteria $searchCriteria -SessionContext $sessionContext -ExcludedProcessIds $excludedProcessIds
if ($null -eq $initialScan) {
    Write-CustomLog "Failed to enumerate processes (EnumProcesses API failure). Exiting with code 17."
    Stop-Script 17
}
Write-ScanReport -ScanResult $initialScan
# A critical process matched by a wildcard, a path or a DLL reveals a pattern that is too broad : the request is refused as a whole
# A critical process matched by a window title (an Explorer folder window for instance) is only left out, the other targets remain valid
$targetItems = @(); $blockingItems = @(); $ignoredItems = @()
foreach ($foundItem in $initialScan.Items) {
    if (-not $foundItem.CriticalReason) { $targetItems += ,$foundItem }
    elseif ($foundItem.Source -eq 'Title') { $ignoredItems += ,$foundItem }
    else { $blockingItems += ,$foundItem }
}
if ($blockingItems.Count -gt 0) {
    Write-CriticalMatchReport -CriticalItems $blockingItems
    Close-TargetItemHandle $initialScan.Items
    Stop-Script 16
}
foreach ($ignoredItem in $ignoredItems) { Write-CustomLog ("WARNING : window '{0}' belongs to the critical system process {1}, it is left out" -f $ignoredItem.Description,$ignoredItem.Name) }
Close-TargetItemHandle $ignoredItems
if ($targetItems.Count -eq 0) {
    Write-CustomLog "No requested processes are currently running. Exiting with code 2."
    Stop-Script 2
}

# --- Popup ---
# The backend proceeds once every popup has proven that it was displayed (SHOWN signal). A popup that was shown and then killed,
# or that outlived its deadline, still counts as a warning given to the user. A popup that never appeared stops everything (exit code 30)
$wasPopupShown = $false
if ($NoPopup) { Write-CustomLog "No -PopupTitle provided : closing without popup." }
else {
    $reachableSessions = @()
    if ($sessionContext.IsSystem) { $reachableSessions = $sessionContext.ActiveUserSessions }
    elseif ($sessionContext.IsProcessInteractive) {
        $reachableSessions = @(@{ SessionId=[int]$sessionContext.CurrentProcessSessionId; FullName=$sessionContext.Name })
        foreach ($activeUserSession in $sessionContext.ActiveUserSessions) {
            if ($activeUserSession.SessionId -ne $sessionContext.CurrentProcessSessionId) { Write-CustomLog ("WARNING : session {0} ({1}) cannot receive a popup because only SYSTEM can reach another session" -f $activeUserSession.SessionId,$activeUserSession.FullName) }
        }
    }
    elseif ($sessionContext.ActiveUserSessions.Count -gt 0) {
        Write-CustomLog "This process is neither SYSTEM nor interactive, and users are logged on : the popup cannot be displayed -> Not supported."
        Close-TargetItemHandle $targetItems
        Stop-Script 13
    }
    $reachableSessionIds = @{}
    foreach ($reachableSession in $reachableSessions) { $reachableSessionIds[[int]$reachableSession.SessionId] = $true }
    $popupPlans = @()
    foreach ($reachableSession in $reachableSessions) {
        $sessionItems = Select-SessionItem -Items $targetItems -SessionId $reachableSession.SessionId -ReachableSessionIds $reachableSessionIds
        if ($sessionItems.Count -gt 0) { $popupPlans += ,@{ Session=$reachableSession; Items=$sessionItems } }
    }
    if ($popupPlans.Count -eq 0) { Write-CustomLog "No user session to warn : closing without popup." }
    else {
        Add-TargetItemIcon -Items $targetItems
        $unconfirmedSessionIds = @()
        $popupOutputs = @()
        if ($sessionContext.IsSystem) {
            # Every concerned session gets its popup at the same time, then all of them are awaited against one shared deadline
            $popupLaunches = @()
            foreach ($popupPlan in $popupPlans) {
                Write-CustomLog ("Starting popup in session {0} ({1}) for {2} items" -f $popupPlan.Session.SessionId,$popupPlan.Session.FullName,$popupPlan.Items.Count)
                $popupScriptText = New-PopupScript -PopupTitle $PopupTitle -Items $popupPlan.Items -Timer $Timer
                $popupLaunches += ,(Start-UserSessionScript -SessionId $popupPlan.Session.SessionId -ScriptText $popupScriptText -ShowWindow:$script:IsTestMode -LogOutputLines)
            }
            $hasLaunchFailure = $false
            foreach ($popupLaunch in $popupLaunches) { if (-not $popupLaunch.Success) { $hasLaunchFailure = $true } }
            if ($hasLaunchFailure) { Write-CustomLog "A popup could not be started : the popups already displayed are closed without waiting for their countdown." }
            $popupDeadlineUtc = [DateTime]::UtcNow.AddSeconds($Timer + 120)
            foreach ($popupLaunch in $popupLaunches) {
                $popupOutputLines = @()
                if ($popupLaunch.Success -and $hasLaunchFailure) { Close-LaunchContext -LaunchContext $popupLaunch -TerminateProcess }
                elseif ($popupLaunch.Success) { $popupOutputLines = (Wait-UserSessionScript -LaunchContext $popupLaunch -DeadlineUtc $popupDeadlineUtc).Stdout }
                $popupOutputs += ,@{ SessionId=$popupLaunch.SessionId; Lines=$popupOutputLines }
            }
        } else {
            $popupPlan = $popupPlans[0]
            Write-CustomLog ("Starting popup in the current session for {0} items" -f $popupPlan.Items.Count)
            $popupScriptText = New-PopupScript -PopupTitle $PopupTitle -Items $popupPlan.Items -Timer $Timer -RunsInProcess
            $popupOutputs += ,@{ SessionId=$popupPlan.Session.SessionId; Lines=(Invoke-ScriptInProcess -ScriptText $popupScriptText).Stdout }
        }
        foreach ($popupOutput in $popupOutputs) {
            $popupOutcome = Get-PopupOutcome $popupOutput.Lines
            Write-CustomLog ("Popup of session {0} : shown={1}, result={2}" -f $popupOutput.SessionId,$popupOutcome.WasShown,$popupOutcome.Result)
            if (-not $popupOutcome.WasShown) { $unconfirmedSessionIds += ,$popupOutput.SessionId }
            elseif (-not $popupOutcome.Result) { Write-CustomLog ("WARNING : the popup of session {0} was displayed but ended without result (killed, logoff or deadline), the user is considered warned" -f $popupOutput.SessionId) }
        }
        if ($unconfirmedSessionIds.Count -gt 0) {
            Write-CustomLog ("ERROR : the popup could not be displayed in session(s) " + ($unconfirmedSessionIds -join ", ") + " : nothing is closed. Exit code : 30")
            Close-TargetItemHandle $targetItems
            Stop-Script 30
        }
        $wasPopupShown = $true
    }
}

# --- Close ---
if ($script:IsTestMode) {
    Write-CustomLog "Test mode -> not closing processes."
    Close-TargetItemHandle $targetItems
    Stop-Script 0
}
Write-CustomLog "Closing detected processes..."
# The processes are scanned again before the first pass when a popup was displayed, because the countdown leaves time for applications to start or exit
Stop-TargetProcess -InitialItems $targetItems -SearchCriteria $searchCriteria -SessionContext $sessionContext -ExcludedProcessIds $excludedProcessIds -Attempts $Attempts -RescanBeforeFirstPass $wasPopupShown
Stop-Script 0
