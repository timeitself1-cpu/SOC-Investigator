"""Generate SYNTHETIC Windows event XML for the windows-replay backend and tests.

These files are authored, not captured from a real machine. They follow the
Windows event XML schema and the documented EventData field names of Sysmon
(v15 schema), Windows Security auditing, PowerShell Operational and Microsoft
Defender Operational, in the form ``wevtutil qe <channel> /f:xml /e:Events``
produces. They exist so the Windows pipeline (parsing, normalization,
discovery, signals, investigation) is testable anywhere. They do NOT show that
the live reader works on Windows; see docs/validation/v0.3/.

Scenarios (host DESKTOP-RW01, 2026-09-29 UTC), mirroring the real-world
validation procedure:
  06:00  Defender detects the EICAR test file (safe standard test string).
  09:00  G:     Intune Management Extension runs an inventory script (benign).
  10:41  RW-01: user-launched hidden encoded PowerShell contacts example.com.
  10:50  RW-03: encoded PowerShell -> cmd -> whoami / ping (multi-generation).
  11:05  RW-04: six failed logons for a non-existent local account.
Plus routine background activity so capability discovery sees each source.

``demo-no-sysmon`` (host DESKTOP-RW05) models RW-05: Sysmon is not installed;
Security process auditing (4688) and PowerShell logging are present.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

OUT = Path(__file__).resolve().parent / "investigator" / "windows_samples"
DAY = datetime(2026, 9, 29, tzinfo=timezone.utc)

PROVIDERS = {
    "sysmon": ("Microsoft-Windows-Sysmon", "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
               "Microsoft-Windows-Sysmon/Operational"),
    "security": ("Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-a5ba-3e3b0328c30d}", "Security"),
    "powershell": ("Microsoft-Windows-PowerShell", "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
                   "Microsoft-Windows-PowerShell/Operational"),
    "defender": ("Microsoft-Windows-Windows Defender", "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}",
                 "Microsoft-Windows-Windows Defender/Operational"),
}
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
EXPLORER = r"C:\Windows\explorer.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
IME = r"C:\Program Files (x86)\Microsoft Intune Management Extension\AgentExecutor.exe"
USER = r"DESKTOP-RW01\rwtest"
SYSTEM = r"NT AUTHORITY\SYSTEM"


def enc(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


def guid(n: int) -> str:
    return "{7c3a9e51-%04x-66f9-%04x-%012x}" % (0x0b00 + n % 0xff, 0x2a00 + n % 0xff, 0x10000 + n)


class Log:
    def __init__(self, host: str) -> None:
        self.host = host
        self.records: dict[str, list[str]] = {k: [] for k in PROVIDERS}
        self.next_id = {"sysmon": 481_200, "security": 902_310, "powershell": 12_040, "defender": 3_310}

    def add(self, source: str, event_id: int, t: datetime, data: dict[str, str], *, pid: int = 3120,
            level: int = 4, sid: str = "S-1-5-18") -> None:
        name, pguid, channel = PROVIDERS[source]
        rec = self.next_id[source]
        self.next_id[source] += 1
        st = t + timedelta(milliseconds=3)
        system_time = st.strftime("%Y-%m-%dT%H:%M:%S.") + f"{st.microsecond:06d}0Z"
        fields = "".join(f"<Data Name={quoteattr(k)}>{escape(v)}</Data>" for k, v in data.items())
        self.records[source].append(
            f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
            f"<Provider Name='{name}' Guid='{pguid}'/><EventID>{event_id}</EventID><Version>5</Version>"
            f"<Level>{level}</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>"
            f"<TimeCreated SystemTime='{system_time}'/><EventRecordID>{rec}</EventRecordID><Correlation/>"
            f"<Execution ProcessID='{pid}' ThreadID='{pid + 1188}'/><Channel>{channel}</Channel>"
            f"<Computer>{self.host}</Computer><Security UserID='{sid}'/></System>"
            f"<EventData>{fields}</EventData></Event>")

    # -- Sysmon ------------------------------------------------------------
    @staticmethod
    def _utc(t: datetime) -> str:
        return t.strftime("%Y-%m-%d %H:%M:%S.") + f"{t.microsecond // 1000:03d}"

    def proc(self, t, g, pid, image, cmd, pg, ppid, pimage, pcmd, user=USER, integrity="Medium", security=True):
        sha = "%064x" % (hash(image) & (2**256 - 1))
        self.add("sysmon", 1, t, {
            "RuleName": "-", "UtcTime": self._utc(t), "ProcessGuid": g, "ProcessId": str(pid), "Image": image,
            "FileVersion": "10.0.22621.1", "Description": image.rsplit("\\", 1)[-1], "Product": "-",
            "Company": "-", "OriginalFileName": image.rsplit("\\", 1)[-1], "CommandLine": cmd,
            "CurrentDirectory": "C:\\Users\\rwtest\\", "User": user, "LogonGuid": "{7c3a9e51-0001-66f9-2a00-000000001000}",
            "LogonId": "0x3e1a2", "TerminalSessionId": "1", "IntegrityLevel": integrity,
            "Hashes": f"SHA256={sha[:64].upper()},IMPHASH={sha[:32].upper()}", "ParentProcessGuid": pg,
            "ParentProcessId": str(ppid), "ParentImage": pimage, "ParentCommandLine": pcmd, "ParentUser": user})
        if security:  # Security 4688 mirrors process creation when process auditing is on
            dom, name = user.split("\\")
            self.add("security", 4688, t + timedelta(milliseconds=1), {
                "SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": name, "SubjectDomainName": dom,
                "SubjectLogonId": "0x3e1a2", "NewProcessId": hex(pid), "NewProcessName": image,
                "TokenElevationType": "%%1938", "ProcessId": hex(ppid), "CommandLine": cmd,
                "TargetUserSid": "S-1-0-0", "TargetUserName": "-", "TargetDomainName": "-", "TargetLogonId": "0x0",
                "ParentProcessName": pimage, "MandatoryLabel": "S-1-16-8192"}, pid=4)

    def end(self, t, g, pid, image, user=USER):
        self.add("sysmon", 5, t, {"RuleName": "-", "UtcTime": self._utc(t), "ProcessGuid": g,
                                  "ProcessId": str(pid), "Image": image, "User": user})

    def net(self, t, g, pid, image, dst, port, host="", user=USER, src="192.168.1.50", sport=50000):
        self.add("sysmon", 3, t, {
            "RuleName": "-", "UtcTime": self._utc(t), "ProcessGuid": g, "ProcessId": str(pid), "Image": image,
            "User": user, "Protocol": "tcp", "Initiated": "true", "SourceIsIpv6": "false", "SourceIp": src,
            "SourceHostname": self.host, "SourcePort": str(sport), "SourcePortName": "-",
            "DestinationIsIpv6": "false", "DestinationIp": dst, "DestinationHostname": host or "-",
            "DestinationPort": str(port), "DestinationPortName": "https" if port == 443 else "-"})

    def dns(self, t, g, pid, image, name, results, user=USER):
        self.add("sysmon", 22, t, {"RuleName": "-", "UtcTime": self._utc(t), "ProcessGuid": g,
                                   "ProcessId": str(pid), "QueryName": name, "QueryStatus": "0",
                                   "QueryResults": results, "Image": image, "User": user})

    # -- Security / PowerShell / Defender -----------------------------------
    def logon(self, t, event_id, user, logon_type, ip="-", status=None):
        dom, name = user.split("\\")
        data = {"SubjectUserSid": "S-1-5-18", "SubjectUserName": self.host + "$", "SubjectDomainName": "WORKGROUP",
                "SubjectLogonId": "0x3e7", "TargetUserSid": "S-1-0-0" if event_id == 4625 else "S-1-5-18",
                "TargetUserName": name, "TargetDomainName": dom}
        if event_id == 4625:
            data.update({"Status": "0xc000006d", "FailureReason": "%%2313", "SubStatus": status or "0xc0000064"})
        else:
            data.update({"TargetLogonId": "0x4f1c2"})
        data.update({"LogonType": str(logon_type), "LogonProcessName": "seclogo" if logon_type == 2 else "Advapi",
                     "AuthenticationPackageName": "Negotiate", "WorkstationName": self.host,
                     "ProcessId": "0x5d4", "ProcessName": SVCHOST, "IpAddress": ip, "IpPort": "0"})
        self.add("security", event_id, t, data, pid=4, level=0)

    def privileges(self, t, user=SYSTEM):
        dom, name = user.split("\\")
        self.add("security", 4672, t, {"SubjectUserSid": "S-1-5-18", "SubjectUserName": name,
                                       "SubjectDomainName": dom, "SubjectLogonId": "0x3e7",
                                       "PrivilegeList": "SeAssignPrimaryTokenPrivilege\n\t\t\tSeTcbPrivilege"},
                 pid=4, level=0)

    def script(self, t, pid, text, path=""):
        self.add("powershell", 4104, t, {"MessageNumber": "1", "MessageTotal": "1", "ScriptBlockText": text,
                                         "ScriptBlockId": "7d9c4f0e-%04x-4f3a-9c1e-0a8b2c3d4e5f" % (pid % 0xffff),
                                         "Path": path}, pid=pid, level=5, sid="S-1-5-21-1-2-3-1001")

    def defender(self, t, event_id, threat, path, process, action):
        self.add("defender", event_id, t, {
            "Product Name": "Microsoft Defender Antivirus", "Product Version": "4.18.24080.9",
            "Detection ID": "{9b1e3c2a-4d5f-4a6b-8c7d-0e1f2a3b4c5d}", "Detection Time": t.isoformat(),
            "Threat ID": "2147519003", "Threat Name": threat, "Severity ID": "5", "Severity Name": "Severe",
            "Category ID": "42", "Category Name": "Virus", "FWLink": "https://go.microsoft.com/fwlink/?linkid=37020",
            "Status Code": "1" if event_id == 1116 else "3", "State": "1", "Source ID": "3",
            "Source Name": "Real-Time Protection", "Process Name": process, "Detection User": USER,
            "Path": path, "Origin ID": "4", "Origin Name": "Internet", "Execution ID": "0",
            "Execution Name": "Unknown", "Type ID": "0", "Type Name": "Concrete",
            "Action ID": "9" if event_id == 1116 else "2", "Action Name": "Not Applicable" if event_id == 1116
            else "Quarantine", "Error Code": "0x00000000", "Error Description": "The operation completed successfully.",
            "Security intelligence Version": "AV: 1.419.123.0", "Engine Version": "AM: 1.1.24080.4"},
            pid=4412, level=3 if event_id == 1116 else 4)

    def write(self, directory: Path, facts: dict) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        for source, rows in self.records.items():
            (directory / f"{source}.xml").write_text("<Events>\n" + "\n".join(rows) + "\n</Events>\n",
                                                     encoding="utf-8")
        (directory / "host.json").write_text(json.dumps(facts, indent=2) + "\n", encoding="utf-8")


def background(log: Log, start: datetime, hours: int, with_sysmon: bool = True) -> None:
    """Routine activity: service logons, browser traffic, DNS."""
    for i in range(hours * 6):
        t = start + timedelta(minutes=10 * i)
        log.logon(t, 4624, SYSTEM, 5)
        if i % 6 == 0:
            log.privileges(t + timedelta(milliseconds=2))
        if with_sysmon:
            log.dns(t + timedelta(seconds=20), guid(9001), 6120, EDGE, "www.bing.com", "type:  5 www-bing-com.a-0001.a-msedge.net;")
            log.net(t + timedelta(seconds=21), guid(9001), 6120, EDGE, "13.107.21.200", 443, sport=51000 + i)
            log.net(t + timedelta(seconds=40), guid(9002), 1880, SVCHOST, "192.168.1.1", 53, user=SYSTEM,
                    sport=52000 + i)


def demo() -> Log:
    log = Log("DESKTOP-RW01")
    background(log, DAY + timedelta(hours=5), 7)
    # explorer (long-lived; its creation predates the window, realistic)
    exp_g, exp_pid = guid(1), 5012
    # 06:00 Defender: EICAR test file downloaded by Edge
    t = DAY + timedelta(hours=6)
    eicar = r"file:_C:\Users\rwtest\Downloads\eicar_com.txt"
    log.defender(t, 1116, "Virus:DOS/EICAR_Test_File", eicar, EDGE, "")
    log.defender(t + timedelta(seconds=2), 1117, "Virus:DOS/EICAR_Test_File", eicar, EDGE, "Quarantine")
    # 09:00 G: Intune inventory script (benign)
    t = DAY + timedelta(hours=9)
    ime_g, ime_pid = guid(10), 7440
    ps_g, ps_pid = guid(11), 7512
    script = r"C:\Program Files (x86)\Microsoft Intune Management Extension\Policies\Scripts\3f2b9c1e_inventory.ps1"
    log.proc(t, ps_g, ps_pid, PS, f'"{PS}" -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{script}"',
             ime_g, ime_pid, IME, f'"{IME}" -powershell -file "{script}"', user=SYSTEM, integrity="System")
    log.script(t + timedelta(seconds=1), ps_pid, "Get-CimInstance -ClassName Win32_BIOS | "
               "Select-Object SerialNumber, SMBIOSBIOSVersion | ConvertTo-Json -Compress", script)
    log.end(t + timedelta(seconds=3), ps_g, ps_pid, PS, user=SYSTEM)
    # 10:41 RW-01: suspicious PowerShell (encoded, hidden) contacting example.com
    t = DAY + timedelta(hours=10, minutes=41)
    rw1 = ("Write-Output 'RW-01 soc-investigator validation'; "
           "Invoke-WebRequest -UseBasicParsing -Uri https://example.com/ | Out-Null")
    g1, p1 = guid(21), 8840
    log.proc(t, g1, p1, PS, f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {enc(rw1)}",
             exp_g, exp_pid, EXPLORER, EXPLORER)
    log.script(t + timedelta(milliseconds=600), p1, rw1)
    log.dns(t + timedelta(seconds=1), g1, p1, PS, "example.com", "93.184.215.14;")
    log.net(t + timedelta(seconds=1, milliseconds=200), g1, p1, PS, "93.184.215.14", 443, "example.com", sport=53011)
    log.end(t + timedelta(seconds=3), g1, p1, PS)
    # 10:50 RW-03: encoded PowerShell -> cmd -> whoami, ping
    t = DAY + timedelta(hours=10, minutes=50)
    rw3 = ("Start-Process -Wait -WindowStyle Hidden cmd.exe "
           "-ArgumentList '/c whoami /all > NUL & ping -n 1 127.0.0.1 > NUL'")
    g3, p3 = guid(31), 9104
    gc, pc = guid(32), 9188
    gw, pw = guid(33), 9220
    gp, pp = guid(34), 9244
    cmdline = "cmd.exe /c whoami /all > NUL & ping -n 1 127.0.0.1 > NUL"
    log.proc(t, g3, p3, PS, f"powershell.exe -NoProfile -EncodedCommand {enc(rw3)}", exp_g, exp_pid, EXPLORER, EXPLORER)
    log.script(t + timedelta(milliseconds=500), p3, rw3)
    log.proc(t + timedelta(seconds=1), gc, pc, CMD, f'"{CMD}" /c whoami /all > NUL & ping -n 1 127.0.0.1 > NUL',
             g3, p3, PS, f"powershell.exe -NoProfile -EncodedCommand {enc(rw3)}")
    log.proc(t + timedelta(seconds=1, milliseconds=300), gw, pw, r"C:\Windows\System32\whoami.exe", "whoami  /all",
             gc, pc, CMD, cmdline)
    log.end(t + timedelta(seconds=1, milliseconds=900), gw, pw, r"C:\Windows\System32\whoami.exe")
    log.proc(t + timedelta(seconds=2), gp, pp, r"C:\Windows\System32\PING.EXE", "ping  -n 1 127.0.0.1",
             gc, pc, CMD, cmdline)
    log.end(t + timedelta(seconds=3), gp, pp, r"C:\Windows\System32\PING.EXE")
    log.end(t + timedelta(seconds=3, milliseconds=100), gc, pc, CMD)
    log.end(t + timedelta(seconds=3, milliseconds=200), g3, p3, PS)
    # 11:05 RW-04: six failed logons for a non-existent local account
    t = DAY + timedelta(hours=11, minutes=5)
    for i in range(6):
        log.logon(t + timedelta(seconds=7 * i), 4625, r"DESKTOP-RW01\rw_nonexistent", 2, ip="::1")
    return log


def demo_no_sysmon() -> Log:
    log = Log("DESKTOP-RW05")
    background(log, DAY + timedelta(hours=8), 4, with_sysmon=False)
    t = DAY + timedelta(hours=10, minutes=41)
    rw1 = ("Write-Output 'RW-05 soc-investigator validation'; "
           "Invoke-WebRequest -UseBasicParsing -Uri https://example.com/ | Out-Null")
    log.proc(t, guid(51), 4412, PS, f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {enc(rw1)}",
             guid(1), 5012, EXPLORER, EXPLORER, user=r"DESKTOP-RW05\rwtest")
    log.script(t + timedelta(milliseconds=600), 4412, rw1)
    log.records["sysmon"] = []  # Sysmon is not installed on this host
    return log


def write() -> None:
    demo().write(OUT / "demo", {"os": "Windows 11 Pro 23H2 build 22631 (synthetic sample)", "elevated": "yes",
                                "role": "Standalone Windows endpoint (synthetic demo data)"})
    demo_no_sysmon().write(OUT / "demo-no-sysmon", {
        "os": "Windows 11 Pro 23H2 build 22631 (synthetic sample)", "elevated": "yes",
        "role": "Standalone Windows endpoint (synthetic demo data)", "missing_sources": "sysmon"})
    (OUT / "demo-no-sysmon" / "sysmon.xml").unlink(missing_ok=True)
    print(f"wrote synthetic samples to {OUT}")


if __name__ == "__main__":
    write()
