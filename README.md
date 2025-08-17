<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/daberrios9/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management has raised concerns regarding possible employee use of the Tor Browser to circumvent network security controls. This concern stems from recent network logs indicating abnormal encrypted traffic patterns and connections to known Tor entry nodes. Additionally, anonymous reports suggest that employees have been discussing methods to access restricted websites during work hours. The objective is to identify any instances of Tor usage, investigate associated security incidents, and take appropriate mitigation measures. Any confirmed use of Tor must be promptly reported to management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “system” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.exe” on the desktop at 2025-08-04T18:35:40.9993302Z.


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunting-"
| where InitiatingProcessAccountName == "system"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-08-05T00:27:32.682977Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any 'ProcessCommandLine' that contained the string "tor-browser-windows-x86_64-portable-14.5.5.exe". At 10:53:18 PM on August 4, 2025, the user cyberuser on the computer "threat-hunting-" ran a file named tor-browser-windows-x86_64-portable-14.5.5.exe from their Downloads folder, which is the installer or portable version of the Tor Browser, and its file fingerprint (SHA-256) was 6d38a13c6a5865b373ef1e1ffcd31b3f359abe896571d27fa666ce71c486a40d.


**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunting-"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents for any indication that user “cyberuser” actually opened the tor browser. There was evidence that they did open it at 2025-08-05T02:53:51.7309195Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunting-"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the tor ports. At 2025-08-05T02:54:26.9637231Z, the computer named "threat-hunting-" successfully connected from the program firefox.exe located at C:\Users\cyberuser\Desktop\Tor Browser\Browser\firefox.exe to the local IP address 127.0.0.1 on port 9150. There were a couple of other connections to sites over port 443.


**Query used to locate events:**

```kql
| where DeviceName == "threat-hunting-"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", “80”, “443”)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

# Incident Timeline: Tor Browser Activity

## 1 — Tor Browser Installer Executed
- **Timestamp:** 2025-08-04T22:53:18Z  
- **Action:** Process execution (Tor Browser installer run)  
- **Event:** User `cyberuser` executed the Tor Browser portable installer from the Downloads folder.  
- **Command:** `tor-browser-windows-x86_64-portable-14.5.5.exe`  
- **File Path:** `C:\Users\cyberuser\Downloads\`

---

## 2 — Tor Files Placed on Desktop
- **Timestamp:** 2025-08-04T22:54:02Z  
- **Action:** File creation / modification (Tor-related files placed on desktop)  
- **Event:** Tor-related files, including the Tor Browser components, were copied to the desktop under the `Tor Browser` folder.  
- **Command:** `tor.exe`  
- **File Path:** `C:\Users\cyberuser\Desktop\Tor Browser\Browser\Tor`

---

## 3 — Suspicious File Created (tor-shopping-list.exe)
- **Timestamp:** 2025-08-04T18:35:40.9993302Z  
- **Action:** File creation (Suspicious executable created)  
- **Event:** A file named `tor-shopping-list.exe` was created on the desktop, potentially unrelated to standard Tor installation.  
- **Command:** `tor-shopping-list.exe`  
- **File Path:** `C:\Users\cyberuser\Desktop\`

---

## 4 — Tor Browser Launched
- **Timestamp:** 2025-08-05T02:53:51Z  
- **Action:** Process execution (Tor Browser launched)  
- **Event:** User `cyberuser` launched the Tor Browser executable (`firefox.exe`) from the desktop installation directory.  
- **Command:** `firefox.exe`  
- **File Path:** `C:\Users\cyberuser\Desktop\Tor Browser\Browser\`

---

## 5 — Tor Local SOCKS Proxy Connection Established
- **Timestamp:** 2025-08-05T02:54:26Z  
- **Action:** Network connection (Tor local SOCKS proxy)  
- **Event:** Tor Browser established a local SOCKS proxy connection to `127.0.0.1` on port `9150`.  
- **Command:** `firefox.exe`  
- **File Path:** `C:\Users\cyberuser\Desktop\Tor Browser\Browser\`

---

📌 **Note:** This timeline captures the sequential forensic evidence of the Tor Browser's installation, launch, file generation, and SOCKS proxy network activity.


---

## Summary

Between late evening on August 4 and early morning on August 5, 2025, the user cyberuser downloaded and executed the Tor Browser installer from their Downloads folder. Shortly after execution, system-level actions resulted in the creation and copying of multiple Tor-related files to the desktop, including a suspiciously named file tor-shopping-list.exe. A few hours later, the Tor
Browser was launched, with associated processes (tor.exe, firefox.exe) starting. The browser established a local SOCKS proxy connection on port 9150.
The sequence of events suggests that after installation, the Tor Browser was set up and actively launched, with at least one custom-named executable (tor-shopping-list.exe) appearing in the desktop environment during the process.


---

## Response Taken

Upon identification of the suspicious Tor Browser installation and the creation of the file tor-shopping-list.exe, the affected endpoint was immediately isolated from the network to
prevent further activity. The file and associated Tor installation directory were quarantined for forensic analysis, and the user account was temporarily disabled pending review. Indicators of compromise (IOCs) were documented, and endpoint security controls were updated to detect and block similar activity in the future.

---
