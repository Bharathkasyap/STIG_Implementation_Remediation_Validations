# 🛡️ Unified STIG Implementation Framework – Bharath Devulapalli (VBDev)

> “Hardening is not a task — it’s a discipline. Every control prevents a disaster.”  
> — *Bharath Devulapalli (VBDev)*

This repository offers a comprehensive, multi-platform STIG (Security Technical Implementation Guide) framework to enforce security across **Windows**, **Linux**, and hybrid infrastructure.

📁 All scripts live in `/source/` and follow this structure:
- Implementation logic to apply settings
- Validation check to verify compliance
- Remediation logic if applicable

---

## 🔧 How to Use

- ✅ `stig-master.sh` for Linux
- ✅ `stig-master.ps1` for Windows
- Logs stored in `/logs`
- Scripts stored in `/source`

---

## 📋 STIG Control Index

### 🪟 **Windows 10 STIGs**

| #  | STIG ID            | Description                                      | Implementation | Validation | Remediation |
|----|--------------------|--------------------------------------------------|----------------|------------|-------------|
| 1  | WN10-AU-000010     | Enable Audit: Credential Validation              | [🔧](./source/WN10-AU-000010.md) | ✅ | ✅ |
| 2  | WN10-AU-000015     | Audit: Logon (Success & Failure)                 | [🔧](./source/WN10-AU-000015.md) | ✅ | ✅ |
| 3  | WN10-AU-000020     | Audit: Special Logon                             | [🔧](./source/WN10-AU-000020.md) | ✅ | ✅ |
| 4  | WN10-AU-000025     | Audit: Account Lockout                           | [🔧](./source/WN10-AU-000025.md) | ✅ | ✅ |
| 5  | WN10-AU-000030     | Audit: Security Group Management                 | [🔧](./source/WN10-AU-000030.md) | ✅ | ✅ |
| 6  | WN10-AU-000035     | Audit: User Account Management                   | [🔧](./source/WN10-AU-000035.md) | ✅ | ✅ |
| 7  | WN10-AU-000070     | Audit: Process Creation                          | [🔧](./source/WN10-AU-000070.md) | ✅ | ✅ |
| 8  | WN10-AU-000085     | Audit: Sensitive Privilege Use                   | [🔧](./source/WN10-AU-000085.md) | ✅ | ✅ |
| 9  | WN10-AU-000500     | Set Application Event Log Size ≥ 32MB           | [🔧](./source/WN10-AU-000500.md) | ✅ | ✅ |
| 10 | WN10-AU-000510     | Enable Security Log Retention                    | [🔧](./source/WN10-AU-000510.md) | ✅ | ✅ |
| 11 | WN10-AU-000515     | Set System Log Size ≥ 32MB                       | [🔧](./source/WN10-AU-000515.md) | ✅ | ✅ |
| 12 | WN10-AU-000525     | Restrict Security Log Access to Admins Only      | [🔧](./source/WN10-AU-000525.md) | ✅ | ✅ |
| 13 | WN10-CC-000185     | Disable SMBv1 Protocol                           | [🔧](./source/WN10-CC-000185.md) | ✅ | ✅ |
| 14 | WN10-CC-000140     | Disable Anonymous SID Enumeration                | [🔧](./source/WN10-CC-000140.md) | ✅ | ✅ |
| 15 | WN10-CC-000200     | Disable NetBIOS over TCP/IP                     | [🔧](./source/WN10-CC-000200.md) | ✅ | ✅ |
| 16 | WN10-CC-000225     | Enable LSA Protection                            | [🔧](./source/WN10-CC-000225.md) | ✅ | ✅ |
| 17 | WN10-CC-000070     | Disable Built-in Administrator Account           | [🔧](./source/WN10-CC-000070.md) | ✅ | ✅ |
| 18 | WN10-CC-000085     | Require Ctrl+Alt+Del at Logon                    | [🔧](./source/WN10-CC-000085.md) | ✅ | ✅ |
| 19 | WN10-CC-000095     | Disable Remote Registry Service                  | [🔧](./source/WN10-CC-000095.md) | ✅ | ✅ |
| 20 | WN10-CC-000120     | Disable LM Hash Storage                          | [🔧](./source/WN10-CC-000120.md) | ✅ | ✅ |
| 21 | WN10-CC-000145     | Enforce NTLMv2 Only                              | [🔧](./source/WN10-CC-000145.md) | ✅ | ✅ |
| 22 | WN10-CC-000175     | Disable Windows Installer                        | [🔧](./source/WN10-CC-000175.md) | ✅ | ✅ |
| 23 | WN10-CC-000015     | Disable Autorun on All Drives                    | [🔧](./source/WN10-CC-000015.md) | ✅ | ✅ |
| 24 | WN10-CC-000045     | Disable Control Panel Access                     | [🔧](./source/WN10-CC-000045.md) | ✅ | ✅ |

---

### 🐧 **Linux STIGs (RHEL/CentOS/Rocky)**

| #  | STIG ID            | Description                                      | Implementation | Validation | Remediation |
|----|--------------------|--------------------------------------------------|----------------|------------|-------------|
| 1  | RHEL-07-040370     | Disable SSH Root Login                           | [🔧](./source/RHEL-07-040370.sh) | ✅ | ✅ |
| 2  | RHEL-07-040340     | SSH Protocol 2 Only                              | [🔧](./source/RHEL-07-040340.sh) | ✅ | ✅ |
| 3  | RHEL-07-010250     | Password Max Age 60 Days                         | [🔧](./source/RHEL-07-010250.sh) | ✅ | ✅ |
| 4  | RHEL-07-010280     | Password Min Length 12                           | [🔧](./source/RHEL-07-010280.sh) | ✅ | ✅ |
| 5  | RHEL-07-010375     | Lock Account After 3 Failed Logins               | [🔧](./source/RHEL-07-010375.sh) | ✅ | ✅ |
| 6  | RHEL-07-020230     | Disable Ctrl+Alt+Del                             | [🔧](./source/RHEL-07-020230.sh) | ✅ | ✅ |
| 7  | RHEL-07-030000     | Ensure auditd Service is Enabled                 | [🔧](./source/RHEL-07-030000.sh) | ✅ | ✅ |
| 8  | RHEL-07-020100     | Mount `/tmp` with noexec,nosuid,nodev            | [🔧](./source/RHEL-07-020100.sh) | ✅ | ✅ |
| 9  | RHEL-07-010240     | Password Min Age 7                               | [🔧](./source/RHEL-07-010240.sh) | ✅ | ✅ |
| 10 | RHEL-07-020230     | Time Sync with chronyd                           | [🔧](./source/RHEL-07-020230.sh) | ✅ | ✅ |

---

## 📁 Folder Structure

