# **Close Processes Popup (CPP)**

**Detects running processes by name, path, used DLL, or windows titles. Shows a popup warning (or not), then closes them.**

---

## Features ✨

* 🔎 **Targeting**: Process name, process path, process using specified DLL, or window Title.
* 🔎 **Multiple targeting**: Supports multiple targets per method, and * wildcards.
* 🖥️ **PSADT-like GUI** (WinForms): Cards layout, app icons, live countdown, DPI-aware.
* 👤 **Works from SYSTEM or Admin**: launches UI in the **active user session** (RDP/console) via `CreateProcessAsUser`.
* 🧵 **Secure pipes**: streams between system/user via private pipes (no temp files, no named pipes).
* 🪓 **Reliable closure**: grouped `taskkill /F /T` passes with verification.

---

![CPP](https://github.com/user-attachments/assets/ae58a81c-59cd-4cf5-977c-47520d7a0447)

---

## Why this tool?

PSADT can be too complex if you just want a popup, there is a single script.
Plus, you can target anything.

---

## Arguments 🛠️

- You must specify **at least one** of `-Process`, `-ProcessPath`, or `-ProcessDLL`.
- **If `-PopupTitle` is missing, POPUP will NOT BE SHOWN**. 

| Parameter     | Description                                                                                                                                  | Example                                                            |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `PopupTitle`  | Display name shown in the popup.                                                                                                             | `-PopupTitle "Adobe Acrobat"`                                      |
| `Process`     | Executable names to target. Supports "=" to customize description in popup. Supports `*` wildcards.                                          | `-Process chrome.exe,"AcroRd32=Acrobat Reader"`                    |
| `ProcessPath` | Match processes by **executable path**. Supports `*` wildcards.                                                                              | `-ProcessPath "C:\Program Files\Adobe","C:\Program Files\Google"`  |
| `ProcessDLL`  | Match processes that **have a DLL loaded**. Accepts **filenames** (no slash), **full paths**, and `*` wildcards.                             | `-ProcessDLL acroRd32.dll,"C:\Program Files\Adobe\*.dll"`          |
| `ProcessTitle`| Match windows by title. Supports "=" to filter by process. Supports `*` wildcards.                                                           | `-ProcessTitle *Paint,*wikipedia*=chrome.exe`                      |
| `Timer`       | Seconds before the popup auto-closes and the backend proceeds.                                                                               | `-Timer 300`                                                       |
| `Attempts`    | Number of grouped `taskkill` passes (1s between).                                                                                            | `-Attempts 5`                                                      |
| `Test`        | Shows the GUI and logs, but do **not** kill processes.                                                                                       | `-Test`                                                            |
| `Log`         | File or folder for the log.                                                                                                                  | `-Log "C:\Logs"`                                                   |


---

## Usage Modes & Examples 📘

### Local (run as Admin)

```bat
cmd /c ""C:\Path\CloseProcessPopup.bat" ^
  -Product "ADOBE" ^
  -Process "chrome.exe=Google Chrome","AcroRd32=Acrobat Reader" ^
  -ProcessPath "C:\Program Files\Google","C:\Program Files\Adobe" ^
  -Log "C:\Logs""
```

### From SYSTEM (scheduled task trick)

```bat
schtasks /create /tn "SysCPP" /tr ^
 "cmd /c \"\"C:\Path\CloseProcessPopup.bat\" -Process \"chrome=Google Chrome\" -Product \"Acrobat Reader\"" ^
 /sc onstart /ru SYSTEM
schtasks /run /tn "SysCPP"
schtasks /delete /tn "SysCPP" /f
```

### Remote (workgroup / explicit creds)

```bat
powershell -Ex Bypass -Command "Invoke-Command -ComputerName %TARGET% -Authentication Negotiate -Credential (New-Object System.Management.Automation.PSCredential('%TARGET%\AdminName',(ConvertTo-SecureString 'AdminPassword' -AsPlainText -Force))) -ScriptBlock { param($batContent,$extraArgs) $Dest=\"$($env:SystemRoot)\Temp\CloseProcessPopup.bat\"; $utf8Bom = New-Object System.Text.UTF8Encoding $false; [System.IO.File]::WriteAllText($Dest,$batContent,$utf8Bom); ^& cmd.exe /c \"\"$Dest\" $extraArgs\"; $LASTEXITCODE } -ArgumentList (Get-Content -Path 'C:\SourcePath\CloseProcessPopup.bat' -Raw), '-Process \"chrome=Google Chrome\" -Product \"Acrobat Reader\"'"
```

### Remote (domain context, default auth)

```bat
powershell -Ex Bypass -Command "Invoke-Command -ComputerName %TARGET% -ScriptBlock { param($batContent,$extraArgs) $Dest=\"$($env:SystemRoot)\Temp\CloseProcessPopup.bat\"; $utf8Bom = New-Object System.Text.UTF8Encoding $false; [System.IO.File]::WriteAllText($Dest,$batContent,$utf8Bom); ^& cmd.exe /c \"\"$Dest\" $extraArgs\"; $LASTEXITCODE } -ArgumentList (Get-Content -Path 'C:\SourcePath\CloseProcessPopup.bat' -Raw), '-Process \"chrome=Google Chrome\" -Product \"Acrobat Reader\"'"
```

---

## Return Codes 🔢

| Code | Meaning                                                |
| ---: | ------------------------------------------------------ |
|    0 | Success                                                |
|    1 | Unknown general launch/error                           |
|    2 | No requested processes are currently running           |
|    3 | Timeout waiting helper/popup process                   |
|    4 | Exception during helper/popup launch                   |
|    5 | Failed to create pipe / write to STDIN                 |
|    6 | `WTSEnumerateSessions` failed                          |
|    7 | `WTSQueryUserToken` failed                             |
|    8 | `DuplicateTokenEx` failed                              |
|    9 | `CreateProcessAsUser` failed                           |
|   10 | No Admin nor SYSTEM privilege at launch                |
|   11 | Missing/invalid required arguments                     |
|   12 | Popup exit code unavailable                            |
|   13 | Unsupported context (non-interactive and not SYSTEM)   |
|   14 | Unknown context                                        |
|   15 | Some processes still running after `taskkill` attempts |

---

## How it Works 🔬

### 1) Bootstrap (Batch → PowerShell)

* Tiny **batch launcher** self-reads the file and invokes PowerShell (`Sysnative` aware), escaping quotes.
* The PowerShell backend is executed **in-place**, no external PS1 is required.

### 2) Discovery (Single Pass)

* Parses `-Process` entries; supports `exeName=LabelForPopup`.
* Parses `-ProcessPath` entries.
* Parses `-ProcessDLL` entries. processes are matched by **loaded module** (filename-only when no slash; full path otherwise).
* Parses `-ProcessTitles` entries; supports `YourWindowTitle=FilterByProcess`.
* Enumerates processes via **Win32** (`EnumProcesses`, `QueryFullProcessImageName`) and falls back to WMI (`Win32_Process`) when needed.
* Extracts **app icons** for the UI cards.

### 3) Popup

* Finds the **active interactive session** (RDP or console) with `WTSEnumerateSessions` and `WTSGetActiveConsoleSessionId`.
* If running as **SYSTEM**, duplicates user token (`WTSQueryUserToken` + `DuplicateTokenEx`) and spawns PowerShell in that session with **`CreateProcessAsUser`**.
* Streams the entire WindowHelper/Popup script through a **private, inheritable STDIN pipe** (no named pipe, no file on disk).
* Popup = WinForms app: DPI-aware, draggable window (with prevention of exiting the screen), **bottom-right** placement, countdown.
* You can insert base64 icon in the lateral bar, by completing "$SidebarLogoBase64" variable.

### 4) Closure

* On popup close (user clicks or countdown hits zero), backend performs up to **N grouped passes** of:
  * `taskkill /F /T /IM <names...>` in batches (handles children).
  * Except for windows found via -ProcessTitle, only PID will be closed.
  * 1s sleep between passes.
  * Final verification via WMI; returns `15` if survivor processes remains.

---

## Logging 🧾

* Default: `%windir%\Temp\<PopupTitle>_CloseProcessPopup.log`
* You can pass a directory or a full file path via `-Log`.
  If a folder is supplied, a filename is generated automatically.

---

## Compatibility ✅

* **PowerShell 2.0 → 5.1 tested**
* **Windows 7 → Windows 11 tested**
* Works across **RDP/console** sessions; requires an **interactive session** (returns `22` if none).
* **SCCM/Intune**: Run as SYSTEM for seamless UI in user session.

---

