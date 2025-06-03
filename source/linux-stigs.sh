# 🐧 Linux STIG Remediation Script – RHEL 7
# =========================================
# Author   : Bharath Devulapalli (VBDev)
# Date     : 2025-05-24
# Purpose  : Linux STIG Implementation Script – RHEL 7
# Version  : 1.0
# License  : MIT
#

# Description:
# This script implements key DISA STIGs for Red Hat Enterprise Linux 7 systems.
# Each section handles one STIG ID and performs:
#  - Validation of the existing setting
#  - Remediation if the system is non-compliant
#  - Logging via terminal output
#
# Run this script as root or with sudo privileges.
# It is intended for compliance hardening and security baseline enforcement.
# =========================================

#!/bin/bash

# ===========================
# STIG ID: RHEL-07-040370
# Name: Disable SSH Root Login
# Purpose: Prevent direct root access via SSH
# Why: Direct root SSH access is a major attack vector.
# MITRE ATT&CK: T1021.004 – Remote Services: SSH
# ===========================
CONFIG_FILE="/etc/ssh/sshd_config"

validate() {
  grep -q "^PermitRootLogin no" "$CONFIG_FILE"
}

remediate() {
  sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$CONFIG_FILE" || echo "PermitRootLogin no" >> "$CONFIG_FILE"
  systemctl restart sshd
}

if validate; then
  echo "[✔] Root login is already disabled."
else
  echo "[!] Root login is enabled. Disabling..."
  remediate
  echo "[+] Root login disabled."
fi

# ==============================
# STIG ID: RHEL-07-010250
# Name: Password Maximum Age
# Purpose: Ensure password expiration policy is set to 60 days
# Why: Limits potential damage from compromised accounts
# MITRE ATT&CK: T1078 – Valid Accounts
# ==============================
validate() {
  grep -q '^PASS_MAX_DAYS[[:space:]]\+60' /etc/login.defs
}

remediate() {
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   60/' /etc/login.defs
}

if validate; then
  echo "[✔] PASS_MAX_DAYS is already set to 60."
else
  echo "[!] Updating PASS_MAX_DAYS to 60..."
  remediate
  echo "[+] PASS_MAX_DAYS set to 60."
fi

# ==============================
# STIG ID: RHEL-07-010280
# Name: Password Minimum Length
# Purpose: Require passwords to be at least 12 characters
# Why: Stronger passwords reduce risk of brute-force attacks
# MITRE ATT&CK: T1110 – Brute Force
# ==============================
validate() {
  grep -q '^minlen = 12' /etc/security/pwquality.conf
}

remediate() {
  sed -i 's/^minlen.*/minlen = 12/' /etc/security/pwquality.conf || echo "minlen = 12" >> /etc/security/pwquality.conf
}

if validate; then
  echo "[✔] Password minimum length is compliant."
else
  echo "[!] Setting minimum password length to 12..."
  remediate
  echo "[+] Password policy updated."
fi

# ==============================
# STIG ID: RHEL-07-010375
# Name: Account Lockout After Failed Attempts
# Purpose: Lock account after 3 failed logins
# Why: Prevents brute-force login attempts
# MITRE ATT&CK: T1110 – Brute Force
# ==============================
validate() {
  grep -q 'deny=3' /etc/pam.d/system-auth
}

remediate() {
  echo "auth required pam_faillock.so preauth silent deny=3 unlock_time=900" >> /etc/pam.d/system-auth
  echo "auth [default=die] pam_faillock.so authfail deny=3 unlock_time=900" >> /etc/pam.d/system-auth
}

if validate; then
  echo "[✔] Account lockout policy is compliant."
else
  echo "[!] Applying account lockout policy..."
  remediate
  echo "[+] Account lockout policy applied."
fi

# ==============================
# STIG ID: RHEL-07-020230
# Name: Disable Ctrl+Alt+Del
# Purpose: Prevent accidental or malicious reboots
# Why: Ctrl+Alt+Del may cause unexpected restarts on production systems
# MITRE ATT&CK: T1499 – Endpoint Denial of Service
# ==============================
validate() {
  systemctl is-enabled ctrl-alt-del.target | grep -q masked
}

remediate() {
  systemctl mask ctrl-alt-del.target
  systemctl daemon-reexec
}

if validate; then
  echo "[✔] Ctrl+Alt+Del is already disabled."
else
  echo "[!] Disabling Ctrl+Alt+Del reboot shortcut..."
  remediate
  echo "[+] Ctrl+Alt+Del disabled."
fi

---
## STIG #6: Disable Ctrl+Alt+Del Reboot

**STIG ID**: `RHEL-07-020230`  
**Purpose**: Prevents local denial-of-service  
**Why This Matters**: Prevents local denial-of-service  
**MITRE ATT&CK Mapping**: `T1490`

```
# =============================
# STIG #6
# STIG ID: RHEL-07-020230
# Name: Disable Ctrl+Alt+Del Reboot
# Purpose: Prevents local denial-of-service
# Why: Prevents local denial-of-service
# MITRE ATT&CK: T1490
# =============================

# STIG: Enforce Time Sync with chronyd
if timedatectl show | grep -q "NTPSynchronized=yes"; then
  echo "[✔] Time synchronization is active."
else
  yum install -y chrony
  systemctl enable chronyd
  systemctl start chronyd
  echo "[+] chronyd installed and time sync enabled."
fi
```

---
## STIG #7: Ensure auditd is Running

**STIG ID**: `RHEL-07-030000`  
**Purpose**: Enables full system monitoring  
**Why This Matters**: Enables full system monitoring  
**MITRE ATT&CK Mapping**: `T1562`

```
# =============================
# STIG #7
# STIG ID: RHEL-07-030000
# Name: Ensure auditd is Running
# Purpose: Enables full system monitoring
# Why: Enables full system monitoring
# MITRE ATT&CK: T1562
# =============================

# STIG: Ensure auditd is Running
if systemctl is-active --quiet auditd; then
  echo "[✔] auditd is already running."
else
  systemctl enable auditd
  systemctl start auditd
  echo "[+] auditd service started and enabled."
fi
```

---
## STIG #8: Secure /tmp with noexec,nosuid,nodev

**STIG ID**: `RHEL-07-020100`  
**Purpose**: Prevents malware staging/exec  
**Why This Matters**: Prevents malware staging/exec  
**MITRE ATT&CK Mapping**: `T1055`

```
# =============================
# STIG #8
# STIG ID: RHEL-07-020100
# Name: Secure /tmp with noexec,nosuid,nodev
# Purpose: Prevents malware staging/exec
# Why: Prevents malware staging/exec
# MITRE ATT&CK: T1055
# =============================

# STIG: Secure /tmp with noexec,nosuid,nodev
if mount | grep '/tmp' | grep -q 'noexec\|nosuid\|nodev'; then
  echo "[✔] /tmp is already secured."
else
  echo "[!] Securing /tmp mount options..."
  echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
  mount -o remount /tmp
  echo "[+] /tmp secured with noexec,nosuid,nodev."
fi
```

---
## STIG #9: Set Password Min Age (7 Days)

**STIG ID**: `RHEL-07-010240`  
**Purpose**: Blocks password reuse looping  
**Why This Matters**: Blocks password reuse looping  
**MITRE ATT&CK Mapping**: `T1078`

```
# =============================
# STIG #9
# STIG ID: RHEL-07-010240
# Name: Set Password Min Age (7 Days)
# Purpose: Blocks password reuse looping
# Why: Blocks password reuse looping
# MITRE ATT&CK: T1078
# =============================

# STIG: Set Password Min Age (7 Days)
if grep -q '^PASS_MIN_DAYS\s\+7' /etc/login.defs; then
  echo "[✔] PASS_MIN_DAYS is already set to 7."
else
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
  echo "[+] PASS_MIN_DAYS set to 7."
fi
```

---
## STIG #10: Enforce Time Sync with chronyd

**STIG ID**: `RHEL-07-020230`  
**Purpose**: Ensures accurate forensic timestamps  
**Why This Matters**: Ensures accurate forensic timestamps  
**MITRE ATT&CK Mapping**: `T1070.006`

```
# =============================
# STIG #10
# STIG ID: RHEL-07-020230
# Name: Enforce Time Sync with chronyd
# Purpose: Ensures accurate forensic timestamps
# Why: Ensures accurate forensic timestamps
# MITRE ATT&CK: T1070.006
# =============================

# STIG: Enforce Time Sync with chronyd
if timedatectl show | grep -q "NTPSynchronized=yes"; then
  echo "[✔] Time synchronization is active."
else
  yum install -y chrony
  systemctl enable chronyd
  systemctl start chronyd
  echo "[+] chronyd installed and time sync enabled."
fi
```

---



















# =========================================
# Author   : Bharath Devulapalli (VBDev)
# Date     : 2025-05-24
# Purpose  : Linux STIG Implementation Script – RHEL 7
# Version  : 1.0
# License  : MIT
#
# Description:
# This script implements key DISA STIGs for Red Hat Enterprise Linux 7 systems.
# Each section handles one STIG ID and performs:
#  - Validation of the existing setting
#  - Remediation if the system is non-compliant
#  - Logging via terminal output
#
# Run this script as root or with sudo privileges.
# It is intended for compliance hardening and security baseline enforcement.
# =========================================

#!/bin/bash

# ===========================
# STIG ID: RHEL-07-040370
# Name: Disable SSH Root Login
# Purpose: Prevent direct root access via SSH
# Why: Direct root SSH access is a major attack vector.
# MITRE ATT&CK: T1021.004 – Remote Services: SSH
# ===========================
CONFIG_FILE="/etc/ssh/sshd_config"

validate() {
  grep -q "^PermitRootLogin no" "$CONFIG_FILE"
}

remediate() {
  sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$CONFIG_FILE" || echo "PermitRootLogin no" >> "$CONFIG_FILE"
  systemctl restart sshd
}

if validate; then
  echo "[✔] Root login is already disabled."
else
  echo "[!] Root login is enabled. Disabling..."
  remediate
  echo "[+] Root login disabled."
fi

# ==============================
# STIG ID: RHEL-07-010250
# Name: Password Maximum Age
# Purpose: Ensure password expiration policy is set to 60 days
# Why: Limits potential damage from compromised accounts
# MITRE ATT&CK: T1078 – Valid Accounts
# ==============================
validate() {
  grep -q '^PASS_MAX_DAYS[[:space:]]\+60' /etc/login.defs
}

remediate() {
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   60/' /etc/login.defs
}

if validate; then
  echo "[✔] PASS_MAX_DAYS is already set to 60."
else
  echo "[!] Updating PASS_MAX_DAYS to 60..."
  remediate
  echo "[+] PASS_MAX_DAYS set to 60."
fi

# ==============================
# STIG ID: RHEL-07-010280
# Name: Password Minimum Length
# Purpose: Require passwords to be at least 12 characters
# Why: Stronger passwords reduce risk of brute-force attacks
# MITRE ATT&CK: T1110 – Brute Force
# ==============================
validate() {
  grep -q '^minlen = 12' /etc/security/pwquality.conf
}

remediate() {
  sed -i 's/^minlen.*/minlen = 12/' /etc/security/pwquality.conf || echo "minlen = 12" >> /etc/security/pwquality.conf
}

if validate; then
  echo "[✔] Password minimum length is compliant."
else
  echo "[!] Setting minimum password length to 12..."
  remediate
  echo "[+] Password policy updated."
fi

# ==============================
# STIG ID: RHEL-07-010375
# Name: Account Lockout After Failed Attempts
# Purpose: Lock account after 3 failed logins
# Why: Prevents brute-force login attempts
# MITRE ATT&CK: T1110 – Brute Force
# ==============================
validate() {
  grep -q 'deny=3' /etc/pam.d/system-auth
}

remediate() {
  echo "auth required pam_faillock.so preauth silent deny=3 unlock_time=900" >> /etc/pam.d/system-auth
  echo "auth [default=die] pam_faillock.so authfail deny=3 unlock_time=900" >> /etc/pam.d/system-auth
}

if validate; then
  echo "[✔] Account lockout policy is compliant."
else
  echo "[!] Applying account lockout policy..."
  remediate
  echo "[+] Account lockout policy applied."
fi

# ==============================
# STIG ID: RHEL-07-020230
# Name: Disable Ctrl+Alt+Del
# Purpose: Prevent accidental or malicious reboots
# Why: Ctrl+Alt+Del may cause unexpected restarts on production systems
# MITRE ATT&CK: T1499 – Endpoint Denial of Service
# ==============================
validate() {
  systemctl is-enabled ctrl-alt-del.target | grep -q masked
}

remediate() {
  systemctl mask ctrl-alt-del.target
  systemctl daemon-reexec
}

if validate; then
  echo "[✔] Ctrl+Alt+Del is already disabled."
else
  echo "[!] Disabling Ctrl+Alt+Del reboot shortcut..."
  remediate
  echo "[+] Ctrl+Alt+Del disabled."
fi
