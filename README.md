# **Close Processes Popup (CPP)**

**Detects running processes by name, path, or DLL, shows a countdown to save work, then closes them.**

---

## Features ✨

* 🔎 **Process discovery**: finds targets by **name** (`chrome.exe`), **path rules** (exact folder or prefix), or **DLL usage**.
* 🖥️ **PSADT-like GUI** (WinForms): Cards layout, app icons, live countdown, DPI-aware.
* 👤 **Works from SYSTEM or Admin**: launches UI in the **active user session** (RDP/console) via `CreateProcessAsUser`.
* 🧵 **Secure pipe**: streams the entire FrontEnd script via **STDIN** (no temp PS1 required).
* 🪓 **Reliable closure**: grouped `taskkill /F /T` passes with verification.

---

![CPP](https://github.com/user-attachments/assets/ae58a81c-59cd-4cf5-977c-47520d7a0447)

---

## Why this tool?

PSADT can be too complex if you just want a popup, there is a single script.

---

## Quick Start 🚀

### Basic (local, elevated)

```bat
cmd /c "CPP.bat -Product "Adobe Acrobat" -Process "AcroRd32.exe=Acrobat Reader","chrome.exe=Google Chrome" -DLL AcroRd32.dll
```

### By folder (exact vs. prefix)

```bat
:: Exact folder and subfolders → end with backslash
-ProcessPath "C:\Program Files\Adobe\"

:: Prefix (starts-with) rule → no trailing backslash
-ProcessPath "C:\Program Files\Adobe"
```

### By DLL (filename, full path or wildcard)

```bat
-ProcessDLL acroRd32.dll,"C:\Program Files\Adobe\*.dll"
```

---

## Arguments 🛠️

`-Product` is **required**. You must specify **at least one** of `-Process`, `-ProcessPath`, or `-ProcessDLL`.

| Parameter     | Description                                                                                                                                  | Example                                                            |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `Product`     | Display name shown in the popup and used to name logs.                                                                                       | `-Product "Adobe Acrobat"`                                         |
| `Process`     | Executable names to target. If extension is missing, `.exe` is added.                  | `-Process "chrome.exe=Google Chrome","AcroRd32=Acrobat Reader"`        |
| `ProcessPath` | Match processes by **executable path**. **With trailing `\`** = exact folder (that folder + subfolders). **Without** = prefix (starts-with). | `-ProcessPath "C:\Program Files\Adobe","C:\Program Files\Google"` |
| `ProcessDLL`  | Match processes that **have a DLL loaded**. Accepts **filenames** (no slash), **full paths**, and `*` wildcards.                             | `-ProcessDLL acroRd32.dll,"C:\Program Files\Adobe\*.dll"`          |
| `Timer`       | Seconds before the popup auto-closes and the backend proceeds.                                                                               | `-Timer 300`                                                       |
| `Attempts`    | Number of grouped `taskkill` passes (1s between).                                                                                            | `-Attempts 5`                                                      |
| `Test`        | Shows the GUI and logs, but do **not** kill processes.                                                                          | `-Test`                                                            |
| `Log`         | File or folder for the log.                                                                    | `-Log "C:\Logs"`                                                   |


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
|    0 | Success (FrontEnd executed)                            |
|    1 | Unknown general launch/error                           |
|    2 | No requested processes are currently running           |
|    3 | Timeout waiting FrontEnd process                       |
|    4 | Exception during FrontEnd launch                       |
|    5 | Failed to create pipe / write to STDIN                 |
|    6 | `WTSEnumerateSessions` failed                          |
|    7 | `WTSQueryUserToken` failed                             |
|    8 | `DuplicateTokenEx` failed                              |
|    9 | `CreateProcessAsUser` failed                           |
|   10 | No Admin nor SYSTEM privilege at launch                |
|   11 | Missing/invalid required arguments                     |
|   12 | FrontEnd exit code unavailable                         |
|   13 | Unsupported context (non-interactive and not SYSTEM)   |
|   14 | Unknown context                                        |
|   15 | Some processes still running after `taskkill` attempts |

---

## How it Works 🔬

### 1) Bootstrap (Batch → PowerShell)

* Tiny **batch launcher** self-reads the file and invokes PowerShell (`Sysnative` aware), escaping quotes.
* The PowerShell backend is executed **in-place**, no external PS1 is required.

### 2) Discovery (Single Pass)

* Parses `-Process` entries; supports `exe=Label`.
* Builds **path rules** from `-ProcessPath`:
  * **Exact folder** if the path ends with `\` (that folder + subfolders only).
  * **Prefix** if no trailing `\` (starts-with, e.g., “Google” also matches “Google Drive”).
* If `-ProcessDLL` is used, processes are matched by **loaded module** (filename-only when no slash; full path otherwise; `*` supported).
* Enumerates processes via **Win32** (`EnumProcesses`, `QueryFullProcessImageName`) and falls back to WMI (`Win32_Process`) when needed.
* Extracts **app icons** (Base64 PNG) for the UI cards.

### 3) Session Hop & FrontEnd

* Finds the **active interactive session** (RDP or console) with `WTSEnumerateSessions` and `WTSGetActiveConsoleSessionId`.
* If running as **SYSTEM**, duplicates user token (`WTSQueryUserToken` + `DuplicateTokenEx`) and spawns PowerShell in that session with **`CreateProcessAsUser`**.
* Streams the entire FrontEnd script through a **private, inheritable STDIN pipe** (no named pipe, no file on disk).
* FrontEnd = WinForms app: DPI-aware, draggable window (with prevention of exiting the screen), **bottom-right** placement, countdown.
* You can insert base64 icon in the lateral bar, by completing "$SidebarLogoBase64" variable.

### 4) Closure Strategy

* On popup close (user clicks or countdown hits zero), backend performs up to **N grouped passes** of:
  * `taskkill /F /T /IM <names...>` in batches (handles children).
  * 1s sleep between passes.
  * Final verification via WMI; returns `15` if survivor processes remains.

---

## Security Notes 🔒

* Requires **Administrator** or **SYSTEM** at launch (returns `10` otherwise).
* The FrontEnd transport uses a **parent-owned anonymous pipe**; write handle is marked **non-inheritable** for child; nothing is **listening** on a public name.
* No temporary PS script is needed (script is streamed).

---

## Logging 🧾

* Default: `%windir%\Temp\<Product>_CloseProcessPopup.log`
* You can pass a directory or a full file path via `-Log`.
  If a folder is supplied, a filename is generated automatically.

---

## Compatibility ✅

* **PowerShell 2.0 → 5.1 tested**
* **Windows XP → Windows 11**
* **x86/x64** aware, `Sysnative` handled automatically.
* Works across **RDP/console** sessions; requires an **interactive session** (returns `22` if none).
* **SCCM/Intune**: Run as SYSTEM for seamless UI in user session; parse return code for retry/deferral logic.

---

