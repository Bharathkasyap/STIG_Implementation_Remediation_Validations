# 🛡️ Windows 10 STIG Remediation Script (Top 20)
**Author:** Bharath Devulapalli (VBDev)
**Date:** 2025-05-03
**License:** MIT
This document contains all 20 STIG remediations with explanations and complete PowerShell commands.

---

## STIG #1: Enable Credential Validation Auditing

**STIG ID**: `WN10-AU-000010`  
**Purpose**: Tracks valid account logins  
**Why This Matters**: Tracks valid account logins  
**MITRE ATT&CK Mapping**: `T1078`

```
# =============================
# STIG #1
# STIG ID: WN10-AU-000010
# Name: Enable Credential Validation Auditing
# Purpose: Tracks valid account logins
# Why: Tracks valid account logins
# MITRE ATT&CK: T1078
# =============================

if (-not ((auditpol /get /subcategory:"Credential Validation") -match "Success\s*Enabled")) {
    auditpol /set /subcategory:"Credential Validation" /success:enable | Out-Null
    Write-Output "[+] Enabled Credential Validation auditing."
}
```

---
## STIG #2: Disable Telemetry

**STIG ID**: `WN10-CC-000205`  
**Purpose**: Stops sensitive data exfil  
**Why This Matters**: Stops sensitive data exfil  
**MITRE ATT&CK Mapping**: `T1082`

```
# =============================
# STIG #2
# STIG ID: WN10-CC-000205
# Name: Disable Telemetry
# Purpose: Stops sensitive data exfil
# Why: Stops sensitive data exfil
# MITRE ATT&CK: T1082
# =============================

$reg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
New-Item -Path $reg -Force | Out-Null
Set-ItemProperty -Path $reg -Name "AllowTelemetry" -Value 0
Write-Output "[+] Telemetry set to Security level (0)."
```

---
## STIG #3: Disable IP Source Routing

**STIG ID**: `WN10-CC-000025`  
**Purpose**: Prevents spoofed network routes  
**Why This Matters**: Prevents spoofed network routes  
**MITRE ATT&CK Mapping**: `T1040`

```
# =============================
# STIG #3
# STIG ID: WN10-CC-000025
# Name: Disable IP Source Routing
# Purpose: Prevents spoofed network routes
# Why: Prevents spoofed network routes
# MITRE ATT&CK: T1040
# =============================

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2
Write-Output "[+] Disabled IP Source Routing."
```

---
## STIG #4: Disable Lock Screen Camera

**STIG ID**: `WN10-CC-000005`  
**Purpose**: Blocks surveillance entry vector  
**Why This Matters**: Blocks surveillance entry vector  
**MITRE ATT&CK Mapping**: `T1123`

```
# =============================
# STIG #4
# STIG ID: WN10-CC-000005
# Name: Disable Lock Screen Camera
# Purpose: Blocks surveillance entry vector
# Why: Blocks surveillance entry vector
# MITRE ATT&CK: T1123
# =============================

$reg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
New-Item -Path $reg -Force | Out-Null
Set-ItemProperty -Path $reg -Name "NoLockScreenCamera" -Value 1
Write-Output "[+] Lock screen camera disabled."
```

---
## STIG #5: Disable Lock Screen Slideshow

**STIG ID**: `WN10-CC-000010`  
**Purpose**: Avoids data leakage via screen display  
**Why This Matters**: Avoids data leakage via screen display  
**MITRE ATT&CK Mapping**: `T1056`

```
# =============================
# STIG #5
# STIG ID: WN10-CC-000010
# Name: Disable Lock Screen Slideshow
# Purpose: Avoids data leakage via screen display
# Why: Avoids data leakage via screen display
# MITRE ATT&CK: T1056
# =============================

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenSlideshow" -Value 1
Write-Output "[+] Lock screen slideshow disabled."
```

---
## STIG #6: Disable Digest Authentication in WinRM

**STIG ID**: `WN10-CC-000360`  
**Purpose**: Prevents credential sniffing  
**Why This Matters**: Prevents credential sniffing  
**MITRE ATT&CK Mapping**: `T1557`

```
# =============================
# STIG #6
# STIG ID: WN10-CC-000360
# Name: Disable Digest Authentication in WinRM
# Purpose: Prevents credential sniffing
# Why: Prevents credential sniffing
# MITRE ATT&CK: T1557
# =============================

$reg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
New-Item -Path $reg -Force | Out-Null
Set-ItemProperty -Path $reg -Name "AllowDigest" -Value 0
Write-Output "[+] Digest authentication disabled in WinRM."
```

---
## STIG #7: Increase Application Log Size

**STIG ID**: `WN10-AU-000500`  
**Purpose**: Ensures audit trail retention  
**Why This Matters**: Ensures audit trail retention  
**MITRE ATT&CK Mapping**: `T1070`

```
# =============================
# STIG #7
# STIG ID: WN10-AU-000500
# Name: Increase Application Log Size
# Purpose: Ensures audit trail retention
# Why: Ensures audit trail retention
# MITRE ATT&CK: T1070
# =============================

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "MaxSize" -Value 32768
Write-Output "[+] Application log size set to 32MB."
```

---
## STIG #8: Enable Security Log Retention

**STIG ID**: `WN10-AU-000510`  
**Purpose**: Prevents log overwrites  
**Why This Matters**: Prevents log overwrites  
**MITRE ATT&CK Mapping**: `T1070.001`

```
# =============================
# STIG #8
# STIG ID: WN10-AU-000510
# Name: Enable Security Log Retention
# Purpose: Prevents log overwrites
# Why: Prevents log overwrites
# MITRE ATT&CK: T1070.001
# =============================

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "Retention" -Value 1
Write-Output "[+] Security log retention set to Manual."
```

---
## STIG #9: System Log Size Minimum

**STIG ID**: `WN10-AU-000515`  
**Purpose**: Supports forensic investigations  
**Why This Matters**: Supports forensic investigations  
**MITRE ATT&CK Mapping**: `T1070`

```
# =============================
# STIG #9
# STIG ID: WN10-AU-000515
# Name: System Log Size Minimum
# Purpose: Supports forensic investigations
# Why: Supports forensic investigations
# MITRE ATT&CK: T1070
# =============================

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "MaxSize" -Value 32768
Write-Output "[+] System log size set to 32MB."
```

---
## STIG #10: Restrict Security Log Access

**STIG ID**: `WN10-AU-000525`  
**Purpose**: Stops unauthorized log reads  
**Why This Matters**: Stops unauthorized log reads  
**MITRE ATT&CK Mapping**: `T1005`

```
# =============================
# STIG #10
# STIG ID: WN10-AU-000525
# Name: Restrict Security Log Access
# Purpose: Stops unauthorized log reads
# Why: Stops unauthorized log reads
# MITRE ATT&CK: T1005
# =============================

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "CustomSD" -Value "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)"
Write-Output "[+] Security log access restricted to SYSTEM and Admins."
```

---
## STIG #11: Disable SMBv1 Protocol

**STIG ID**: `WN10-CC-000185`  
**Purpose**: Blocks legacy exploit pathways  
**Why This Matters**: Blocks legacy exploit pathways  
**MITRE ATT&CK Mapping**: `T1021.002`

```
# =============================
# STIG #11
# STIG ID: WN10-CC-000185
# Name: Disable SMBv1 Protocol
# Purpose: Blocks legacy exploit pathways
# Why: Blocks legacy exploit pathways
# MITRE ATT&CK: T1021.002
# =============================

Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Write-Output "[+] SMBv1 protocol disabled."
```

---
## STIG #12: Enforce NTLMv2 Authentication

**STIG ID**: `WN10-CC-000145`  
**Purpose**: Prevents NTLM downgrade attacks  
**Why This Matters**: Prevents NTLM downgrade attacks  
**MITRE ATT&CK Mapping**: `T1557.001`

```
# =============================
# STIG #12
# STIG ID: WN10-CC-000145
# Name: Enforce NTLMv2 Authentication
# Purpose: Prevents NTLM downgrade attacks
# Why: Prevents NTLM downgrade attacks
# MITRE ATT&CK: T1557.001
# =============================

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
Write-Output "[+] NTLMv2-only authentication enforced."
```

---
## STIG #13: Disable LM Hash Storage

**STIG ID**: `WN10-CC-000120`  
**Purpose**: Blocks brute force password cracking  
**Why This Matters**: Blocks brute force password cracking  
**MITRE ATT&CK Mapping**: `T1003.001`

```
# =============================
# STIG #13
# STIG ID: WN10-CC-000120
# Name: Disable LM Hash Storage
# Purpose: Blocks brute force password cracking
# Why: Blocks brute force password cracking
# MITRE ATT&CK: T1003.001
# =============================

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
Write-Output "[+] LM hash storage disabled."
```

---
## STIG #14: Disable Remote Registry Service

**STIG ID**: `WN10-CC-000095`  
**Purpose**: Closes remote registry abuse  
**Why This Matters**: Closes remote registry abuse  
**MITRE ATT&CK Mapping**: `T1112`

```
# =============================
# STIG #14
# STIG ID: WN10-CC-000095
# Name: Disable Remote Registry Service
# Purpose: Closes remote registry abuse
# Why: Closes remote registry abuse
# MITRE ATT&CK: T1112
# =============================

Stop-Service -Name RemoteRegistry -Force
Set-Service -Name RemoteRegistry -StartupType Disabled
Write-Output "[+] Remote Registry disabled."
```

---
## STIG #15: Disable Built-in Admin Account

**STIG ID**: `WN10-CC-000070`  
**Purpose**: Removes predictable admin credentials  
**Why This Matters**: Removes predictable admin credentials  
**MITRE ATT&CK Mapping**: `T1078`

```
# =============================
# STIG #15
# STIG ID: WN10-CC-000070
# Name: Disable Built-in Admin Account
# Purpose: Removes predictable admin credentials
# Why: Removes predictable admin credentials
# MITRE ATT&CK: T1078
# =============================

net user Administrator /active:no
Write-Output "[+] Built-in Administrator account disabled."
```

---
## STIG #16: Require Ctrl+Alt+Del at Login

**STIG ID**: `WN10-CC-000085`  
**Purpose**: Stops spoofed login attempts  
**Why This Matters**: Stops spoofed login attempts  
**MITRE ATT&CK Mapping**: `T1056`

```
# =============================
# STIG #16
# STIG ID: WN10-CC-000085
# Name: Require Ctrl+Alt+Del at Login
# Purpose: Stops spoofed login attempts
# Why: Stops spoofed login attempts
# MITRE ATT&CK: T1056
# =============================

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0
Write-Output "[+] Ctrl+Alt+Del required for login."
```

---
## STIG #17: Disable Autorun on All Drives

**STIG ID**: `WN10-CC-000015`  
**Purpose**: Blocks USB-based malware auto exec  
**Why This Matters**: Blocks USB-based malware auto exec  
**MITRE ATT&CK Mapping**: `T1091`

```
# =============================
# STIG #17
# STIG ID: WN10-CC-000015
# Name: Disable Autorun on All Drives
# Purpose: Blocks USB-based malware auto exec
# Why: Blocks USB-based malware auto exec
# MITRE ATT&CK: T1091
# =============================

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
Write-Output "[+] Autorun disabled on all drives."
```

---
## STIG #18: Disable Control Panel Access

**STIG ID**: `WN10-CC-000045`  
**Purpose**: Prevents misconfig by users  
**Why This Matters**: Prevents misconfig by users  
**MITRE ATT&CK Mapping**: `T1546`

```
# =============================
# STIG #18
# STIG ID: WN10-CC-000045
# Name: Disable Control Panel Access
# Purpose: Prevents misconfig by users
# Why: Prevents misconfig by users
# MITRE ATT&CK: T1546
# =============================

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoControlPanel" -Value 1
Write-Output "[+] Control Panel access disabled."
```

---
## STIG #19: Disable Anonymous SID Enumeration

**STIG ID**: `WN10-CC-000140`  
**Purpose**: Restricts attacker enumeration  
**Why This Matters**: Restricts attacker enumeration  
**MITRE ATT&CK Mapping**: `T1087`

```
# =============================
# STIG #19
# STIG ID: WN10-CC-000140
# Name: Disable Anonymous SID Enumeration
# Purpose: Restricts attacker enumeration
# Why: Restricts attacker enumeration
# MITRE ATT&CK: T1087
# =============================

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1
Write-Output "[+] Anonymous SID Enumeration disabled."
```

---
## STIG #20: Disable NetBIOS over TCP/IP

**STIG ID**: `WN10-CC-000200`  
**Purpose**: Prevents legacy net exposure  
**Why This Matters**: Prevents legacy net exposure  
**MITRE ATT&CK Mapping**: `T1016`

```
# =============================
# STIG #20
# STIG ID: WN10-CC-000200
# Name: Disable NetBIOS over TCP/IP
# Purpose: Prevents legacy net exposure
# Why: Prevents legacy net exposure
# MITRE ATT&CK: T1016
# =============================

Get-NetAdapter | ForEach-Object {
    Set-NetBIOSConfiguration -InterfaceAlias $_.Name -NetBIOSOption 2
}
Write-Output "[+] NetBIOS over TCP/IP disabled on all adapters."
```

---
