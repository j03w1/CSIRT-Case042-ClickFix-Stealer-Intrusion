#!/usr/bin/env python3
"""
CSIRT Case 042 - Automated Sysmon Telemetry Triage & IOC Extraction Engine
Author: CSIRT Analyst Portfolio
Description:
    Ingests Windows Sysmon JSON logs, evaluates behavioral detection rules mapped
    to MITRE ATT&CK, automatically decodes Base64 PowerShell payloads, extracts
    and defangs IOCs, and writes a Markdown triage report.
"""

import base64
import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple

TELEMETRY_PATH = Path("data/sysmon_telemetry.json")
REPORT_OUTPUT_PATH = Path("reports/automated_triage_output.md")

IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
URL_REGEX = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
ENC_CMD_REGEX = re.compile(
    r"(?:-EncodedCommand|-enc|-e)\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE
)


def defang_ioc(indicator: str) -> str:
    """Defangs IPv4 addresses, URLs, and domains for safe CSIRT reporting."""
    defanged = indicator.replace("http://", "hxxp://").replace("https://", "hxxps://")
    defanged = defanged.replace(".", "[.]")
    return defanged


def decode_powershell_b64(encoded_str: str) -> str:
    """Attempts to decode Base64 strings as UTF-8 or UTF-16LE."""
    try:
        raw_bytes = base64.b64decode(encoded_str)
        # Check if payload is UTF-16LE (null bytes interleaved) or standard UTF-8
        if b"\x00" in raw_bytes:
            return raw_bytes.decode("utf-16le", errors="replace").strip()
        return raw_bytes.decode("utf-8", errors="replace").strip()
    except Exception as exc:
        return f"<Decode Error: {exc}>"


def evaluate_event(event: Dict) -> List[Tuple[str, str, str, str]]:
    """
    Evaluates a single Sysmon event against CSIRT behavioral heuristics.
    Returns list of tuples: (Severity, MITRE_ID, Rule_Name, Finding_Detail)
    """
    alerts = []
    eid = event.get("EventID")
    image = event.get("Image", "").lower()
    parent = event.get("ParentImage", "").lower()
    cmdline = event.get("CommandLine", "")
    target_file = event.get("TargetFilename", "")
    target_image = event.get("TargetImage", "").lower()

    # Detection 1: ClickFix / Run Dialog spawning mshta.exe
    if eid == 1 and image.endswith("mshta.exe") and parent.endswith("explorer.exe"):
        alerts.append((
            "HIGH",
            "T1218.005 / T1204.004",
            "ClickFix Lure: Explorer Spawned Mshta LOLBin",
            f"Parent `explorer.exe` executed `{cmdline}`"
        ))

    # Detection 2: Obfuscated PowerShell Command Line
    if eid == 1 and image.endswith("powershell.exe") and (
        "-encodedcommand" in cmdline.lower() or "-w hidden" in cmdline.lower()
    ):
        alerts.append((
            "CRITICAL",
            "T1059.001",
            "Hidden / Base64-Encoded PowerShell Execution",
            f"Process `{ event.get('ProcessId') }` executed encoded command via `{parent}`"
        ))

    # Detection 3: Suspicious Executable Dropped in User Temp Directory
    if eid == 11 and "\\appdata\\local\\temp\\" in target_file.lower() and target_file.lower().endswith(".exe"):
        alerts.append((
            "HIGH",
            "T1105",
            "Executable Dropped in User Temp Directory",
            f"`{event.get('Image')}` created `{target_file}` (SHA256: `{event.get('SHA256')}`)"
        ))

    # Detection 4: Scheduled Task Persistence targeting Temp Directory
    if eid == 1 and image.endswith("schtasks.exe") and "/create" in cmdline.lower():
        alerts.append((
            "HIGH",
            "T1053.005",
            "Scheduled Task Persistence Created",
            f"Command: `{cmdline}`"
        ))

    # Detection 5: LSASS Memory Dump via comsvcs.dll MiniDump
    if eid == 10 and target_image.endswith("lsass.exe"):
        alerts.append((
            "CRITICAL",
            "T1003.001",
            "LSASS Process Memory Access / Credential Dumping",
            f"Source `{event.get('SourceImage')}` accessed `lsass.exe` (Access: `{event.get('GrantedAccess')}`) via `{cmdline}`"
        ))

    # Detection 6: Outbound C2 / Unusual Network Connection from Non-Browser Process
    if eid == 3 and not image.endswith(("chrome.exe", "msedge.exe", "firefox.exe")):
        dest_ip = event.get("DestinationIp", "")
        dest_port = event.get("DestinationPort", "")
        dest_host = event.get("DestinationHostname", "")
        alerts.append((
            "HIGH",
            "T1071.001",
            "Suspicious Outbound Network Connection",
            f"Process `{event.get('Image')}` connected to `{dest_ip}:{dest_port}` (`{dest_host}`)"
        ))

    return alerts


def main() -> None:
    if not TELEMETRY_PATH.exists():
        raise FileNotFoundError(f"Missing telemetry file: {TELEMETRY_PATH}")

    with TELEMETRY_PATH.open("r", encoding="utf-8") as f:
        events = json.load(f)

    timeline_findings = []
    decoded_payloads = []
    iocs_ips: Set[str] = set()
    iocs_domains: Set[str] = set()
    iocs_urls: Set[str] = set()
    iocs_hashes: Set[str] = set()
    iocs_files: Set[str] = set()

    for event in events:
        alerts = evaluate_event(event)
        if not alerts:
            continue

        ts = event.get("Timestamp", "Unknown")
        cmdline = event.get("CommandLine", "")

        # Check for Base64 PowerShell payloads
        b64_match = ENC_CMD_REGEX.search(cmdline)
        if b64_match:
            b64_str = b64_match.group(1)
            decoded = decode_powershell_b64(b64_str)
            entry = (ts, event.get("Image", ""), b64_str, decoded)
            if entry not in decoded_payloads:
                decoded_payloads.append(entry)
            for url in URL_REGEX.findall(decoded):
                iocs_urls.add(url)
            for ip in IPV4_REGEX.findall(decoded):
                iocs_ips.add(ip)

        # Extract network and file IOCs from alerted events
        if event.get("DestinationIp"):
            iocs_ips.add(event["DestinationIp"])
        if event.get("DestinationHostname"):
            iocs_domains.add(event["DestinationHostname"])
        if event.get("TargetFilename"):
            iocs_files.add(event["TargetFilename"])
        if event.get("EventID") in (3, 10, 11) and event.get("SHA256"):
            iocs_hashes.add(event["SHA256"])

        for severity, mitre_id, rule_name, detail in alerts:
            timeline_findings.append({
                "timestamp": ts,
                "severity": severity,
                "mitre": mitre_id,
                "rule": rule_name,
                "detail": detail,
                "host": event.get("Host", ""),
                "user": event.get("User", "")
            })

    # Generate Markdown Report
    REPORT_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# 🤖 Automated CSIRT Triage Output (Case 042)",
        "",
        f"* **Total Telemetry Events Analyzed:** `{len(events)}`",
        f"* **High/Critical Security Alerts Triggered:** `{len(timeline_findings)}`",
        f"* **Base64 Payloads Automatically Decoded:** `{len(decoded_payloads)}`",
        "",
        "---",
        "",
        "## Decoded Obfuscated Payloads",
        ""
    ]

    for ts, proc, b64_raw, decoded_str in decoded_payloads:
        lines.extend([
            f"### Timestamp: `{ts}` (`{proc}`)",
            "**Encoded Base64 Snippet:**",
            f"```text\n{b64_raw}\n```",
            "**Decoded Cleartext Payload (Defanged):**",
            f"```powershell\n{defang_ioc(decoded_str)}\n```",
            ""
        ])

    lines.extend([
        "---",
        "",
        "## Reconstructed Attack Timeline",
        "",
        "| Timestamp (UTC) | Severity | MITRE ATT&CK | Detection Rule | Technical Evidence |",
        "| :--- | :--- | :--- | :--- | :--- |"
    ])

    for item in timeline_findings:
        lines.append(
            f"| `{item['timestamp']}` | **{item['severity']}** | `{item['mitre']}` | "
            f"{item['rule']} | {item['detail']} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## Extracted & Defanged Indicators of Compromise (IOCs)",
        "",
        "| IOC Type | Defanged Indicator | Context |",
        "| :--- | :--- | :--- |"
    ])

    for ip in sorted(iocs_ips):
        lines.append(f"| **IPv4 Address** | `{defang_ioc(ip)}` | C2 / Payload Staging Server |")
    for dom in sorted(iocs_domains):
        lines.append(f"| **Domain** | `{defang_ioc(dom)}` | Malicious Hostname |")
    for url in sorted(iocs_urls):
        lines.append(f"| **URL** | `{defang_ioc(url)}` | Stage-1 PowerShell Download Cradle |")
    for fpath in sorted(iocs_files):
        lines.append(f"| **File Path** | `{fpath}` | Dropped Stage-2 Binary |")
    for sha in sorted(iocs_hashes):
        lines.append(f"| **SHA-256** | `{sha}` | Malicious Payload Hash (`sync_helper.exe`) |")

    report_content = "\n".join(lines) + "\n"
    REPORT_OUTPUT_PATH.write_text(report_content, encoding="utf-8")
    print(report_content)


if __name__ == "__main__":
    main()
