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
