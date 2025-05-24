# =========================================
# Author   : Bharath Devulapalli (VBDev)
# Date     : 2025-05-24
# Purpose  : Unified Windows 10 STIG Implementation Script
# Version  : 1.0
# License  : MIT
#
# Description:
# This PowerShell script implements multiple DISA STIG controls
# for Windows 10 systems. It includes validation and remediation
# for each STIG to ensure systems meet baseline security requirements.
#
# Usage:
# - Run as Administrator on Windows 10
# - Each section handles a specific STIG ID
# - Output indicates whether each setting was compliant or fixed
# =========================================

# =============================
# STIG ID: WN10-AU-000010
# Name: Credential Validation Auditing
# Purpose: Enable audit logging of successful credential validation
# Why: Required for login tracking, investigations, and accountability
# MITRE ATT&CK: T1078 – Valid Accounts
# =============================

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script as Administrator."
    exit 1
}

$current = (auditpol /get /subcategory:"Credential Validation") -match "Success.*Enabled"
if ($current) {
    Write-Output "[✔] Credential Validation (Success) auditing is already enabled."
} else {
    auditpol /set /subcategory:"Credential Validation" /success:enable | Out-Null
    Write-Output "[+] Enabled Credential Validation auditing."
}


# =============================
# STIG ID: WN10-CC-000205
# Name: Disable Telemetry
# Purpose: Restrict telemetry level to 'Security'
# Why: Prevents potential leakage of sensitive system data
# MITRE ATT&CK: T1082 – System Information Discovery
# =============================

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "AllowTelemetry" -Value 0 -Type DWord
Write-Output "[+] Telemetry set to 'Security' (0)."


# =============================
# STIG ID: WN10-CC-000025
# Name: Disable IP Source Routing
# Purpose: Prevent spoofing via source routing
# Why: Source routing is exploitable for spoofing attacks
# MITRE ATT&CK: T1040 – Network Sniffing
# =============================

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
Set-ItemProperty -Path $regPath -Name "DisableIPSourceRouting" -Value 2 -Type DWord
Write-Output "[+] IP source routing disabled."


# =============================
# STIG ID: WN10-CC-000005
# Name: Disable Lock Screen Camera
# Purpose: Prevent camera usage on locked screen
# Why: Avoid privacy and surveillance risks
# MITRE ATT&CK: T1123 – Audio Capture
# =============================

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
Set-ItemProperty -Path $regPath -Name "NoLockScreenCamera" -Value 1 -Type DWord
Write-Output "[+] Lock screen camera disabled."


# =============================
# STIG ID: WN10-CC-000010
# Name: Disable Lock Screen Slideshow
# Purpose: Prevent slideshow from revealing sensitive info
# Why: Lock screen may unintentionally display confidential data
# MITRE ATT&CK: T1056 – Input Capture
# =============================

Set-ItemProperty -Path $regPath -Name "NoLockScreenSlideshow" -Value 1 -Type DWord
Write-Output "[+] Lock screen slideshow disabled."


# =============================
# STIG ID: WN10-CC-000360
# Name: Disable Digest Authentication in WinRM
# Purpose: Prevent insecure Digest authentication
# Why: Digest auth can leak credentials
# MITRE ATT&CK: T1557 – Man-in-the-Middle
# =============================

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "AllowDigest" -Value 0 -Type DWord
Write-Output "[+] Digest Authentication disabled in WinRM."


# =============================
# STIG ID: WN10-AU-000500
# Name: Application Log Size Minimum
# Purpose: Set minimum log size to 32MB
# Why: Ensure retention of log data for investigations
# MITRE ATT&CK: T1070 – Indicator Removal on Host
# =============================

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
Set-ItemProperty -Path $regPath -Name "MaxSize" -Value 32768 -Type DWord
Write-Output "[+] Application log size set to 32MB."


# =============================
# STIG ID: WN10-AU-000510
# Name: Security Log Retention
# Purpose: Prevent automatic overwrites of security logs
# Why: Ensures log data is preserved for investigation
# MITRE ATT&CK: T1070.001 – Clear Windows Event Logs
# =============================

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
Set-ItemProperty -Path $regPath -Name "Retention" -Value 1 -Type DWord
Write-Output "[+] Security log retention configured (Manual mode)."


# =============================
# STIG ID: WN10-AU-000515
# Name: System Log Size Minimum
# Purpose: Set system log size to at least 32MB
# Why: Supports event retention and analysis
# MITRE ATT&CK: T1070 – Indicator Removal on Host
# =============================

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
Set-ItemProperty -Path $regPath -Name "MaxSize" -Value 32768 -Type DWord
Write-Output "[+] System event log size set to 32MB."


# =============================
# STIG ID: WN10-AU-000525
# Name: Restrict Security Log Access
# Purpose: Limit access to security logs to admins only
# Why: Prevent unauthorized log tampering or visibility
# MITRE ATT&CK: T1005 – Data from Local System
# =============================

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
Set-ItemProperty -Path $regPath -Name "CustomSD" -Value "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)" -Type String
Write-Output "[+] Security log access restricted to SYSTEM and Admins."


# =============================
# STIG ID: WN10-CC-000185
# Name: Disable SMBv1
# Purpose: Disable insecure SMBv1 protocol
# Why: SMBv1 is deprecated and vulnerable (e.g., WannaCry)
# MITRE ATT&CK: T1021.002 – SMB/Windows Admin Shares
# =============================

Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Write-Output "[+] SMBv1 disabled."


# =============================
# STIG ID: WN10-CC-000145
# Name: Enforce NTLMv2 Only
# Purpose: Disable LM and force NTLMv2 authentication
# Why: Older protocols are weak and easily exploited
# MITRE ATT&CK: T1557.001 – Adversary-in-the-Middle: NTLM Relay
# =============================

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord
Write-Output "[+] NTLMv2-only mode enforced."


# =============================
# STIG ID: WN10-CC-000120
# Name: Disable LM Hash Storage
# Purpose: Prevent storage of weak LAN Manager hashes
# Why: LM hashes are easily cracked
# MITRE ATT&CK: T1003.001 – LSASS Memory
# =============================

Set-ItemProperty -Path $regPath -Name "NoLMHash" -Value 1 -Type DWord
Write-Output "[+] LM hash storage disabled."


# =============================
# STIG ID: WN10-CC-000095
# Name: Disable Remote Registry
# Purpose: Stop remote access to the registry service
# Why: Limits remote attack vectors
# MITRE ATT&CK: T1112 – Modify Registry
# =============================

Stop-Service -Name RemoteRegistry -Force
Set-Service -Name RemoteRegistry -StartupType Disabled
Write-Output "[+] Remote Registry service disabled."


# =============================
# STIG ID: WN10-CC-000070
# Name: Disable Built-in Administrator
# Purpose: Prevent use of default admin account
# Why: Reduces privilege abuse risk
# MITRE ATT&CK: T1078 – Valid Accounts
# =============================

net user Administrator /active:no
Write-Output "[+] Built-in Administrator account disabled."


# =============================
# STIG ID: WN10-CC-000085
# Name: Require Ctrl+Alt+Del at Logon
# Purpose: Force secure login sequence
# Why: Prevents credential harvesting via spoofed screens
# MITRE ATT&CK: T1056 – Input Capture
# =============================

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty -Path $regPath -Name "DisableCAD" -Value 0 -Type DWord
Write-Output "[+] Ctrl+Alt+Del required at logon."


# =============================
# STIG ID: WN10-CC-000015
# Name: Disable Autorun on All Drives
# Purpose: Prevent automatic execution of media
# Why: Blocks malware via USB or CDs
# MITRE ATT&CK: T1091 – Replication Through Removable Media
# =============================

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
Set-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
Write-Output "[+] Autorun disabled for all drive types."


# =============================
# STIG ID: WN10-CC-000045
# Name: Disable Control Panel Access
# Purpose: Prevent standard users from modifying system settings
# Why: Restricts unauthorized configuration changes
# MITRE ATT&CK: T1546 – Event Triggered Execution
# =============================

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
Set-ItemProperty -Path $regPath -Name "NoControlPanel" -Value 1 -Type DWord
Write-Output "[+] Control Panel access disabled."
