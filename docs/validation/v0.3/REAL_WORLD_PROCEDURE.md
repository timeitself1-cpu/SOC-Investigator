# v0.3 real-world validation procedure (one Windows 11 machine)

Purpose: answer the v0.3 go/no-go question — *can the existing investigation engine
perform useful, evidence-grounded investigations directly against real Windows
telemetry, without Wazuh or another SIEM?*

**Status in this repository: NOT RUN.** The development environment for v0.3 was Linux
without a Windows host. Everything below was prepared, and the same pipeline was
exercised on synthetic, schema-faithful event XML (`investigator/windows_samples/`),
but no result here comes from a real Windows machine. Record real results in
[`RESULTS.md`](RESULTS.md) and keep the raw evidence folder.

Safety: the scenarios use built-in Windows tools only (PowerShell, cmd, whoami, ping,
Secondary Logon). No malware, exploit, download-and-execute or configuration change.

## 0. Prerequisites (once)

1. Windows 11, Python 3.12, the project installed (`pip install -e .`, which installs pywin32).
2. Ollama with `qwen2.5:7b-instruct` pulled (or run with `--llm mock` first).
3. Telemetry, as recommended in README → "Telemetry sources":
   * Sysmon with process creation (1), network (3) and DNS (22) logging;
   * `auditpol /set /subcategory:"Process Creation" /success:enable` (+ command-line capture);
   * PowerShell script block logging;
   * Microsoft Defender enabled (default).
4. Your account in **Event Log Readers** (or run the investigator elevated; record which).

## 1. Baseline

```powershell
python -m investigator --backend windows sources          # expect four ✓ (record the output)
python -m investigator --backend windows --llm ollama diagnose
$env:SOCI_BACKEND = "windows"; $env:SOCI_LLM = "ollama"
python -m investigator serve                                # open http://127.0.0.1:8000
```

## 2. Scenarios

Generate each scenario in a **separate** non-elevated PowerShell window, then open the
dashboard, find the signal, click **Investigate**, and export the report (JSON and
Markdown). Leave ≥ 60 minutes between RW-02 and the other scenarios: the host-signal
requirement correctly blocks benign closure while other signals exist within an hour.

```powershell
powershell -ExecutionPolicy Bypass -File docs\validation\v0.3\rw_scenarios.ps1 -Scenario RW01
```

| ID | Generate | Expected signal | Pass criteria |
| --- | --- | --- | --- |
| RW-01 | `-Scenario RW01` | "Suspicious PowerShell (encoded command, hidden window)", high | Investigation starts from the signal. Report cites the Sysmon 1 record of `powershell.exe` with `-EncodedCommand`, its decoded text, the PowerShell 4104 script block, and the DNS (22) / network (3) records for example.com. Process tree shows the parent. `process_tree` and `network_activity` requirements are met. Verdict `suspicious` or `likely_malicious` (not `benign`). `validation.invalid_evidence_refs` is empty. |
| RW-02 | `-Scenario RW02` (≥ 60 min from others) | "Suspicious PowerShell (hidden window)", medium | `process_tree`, `network_activity`, `host_context`, `host_signals`, `model_visibility` all **met**. On an **unmanaged** PC the verdict is expected to be `insufficient_evidence` with the only benign blocker "no finding established administrative context" — benign closure needs a recognized management agent (Intune IME / ConfigMgr) as parent. On an Intune/ConfigMgr-managed PC with a real management script, `benign` is expected to be reachable. Record which case applies. |
| RW-03 | `-Scenario RW03` | "Suspicious PowerShell (encoded command)", medium | Process tree shows `powershell.exe → cmd.exe → whoami.exe` and `→ PING.EXE` (three generations). Grandchildren are evidence with valid references. |
| RW-04 | `-Scenario RW04` | "Repeated failed logons: 5+ failures for <PC>\rw_nonexistent within 10 min", medium | Investigation calls `get_logon_activity` and retrieves ≥ 5 Security 4625 records for the account. Verdict is not `benign`. (If no 4625 events appear, logon-failure auditing is off: `auditpol /get /subcategory:"Logon"`; record that.) |
| RW-05 | see below | — | The dashboard shows the missing/denied source; affected investigations are **incomplete**; no `benign` verdict; failed tool calls have `error_kind` `permission` or `source_unavailable`, never "0 events". |

### RW-05 — missing telemetry (choose one, record which)

* **A. Access denied (recommended, reversible, no system change):** start the investigator
  from a *standard* account that is **not** in Event Log Readers. Expect Sysmon and Windows
  Security `✗ access denied` in `sources` and on the dashboard, signal notes explaining
  which signals are unavailable, and investigations marked incomplete.
* **B. Sysmon not recording (elevated, reversible):** `sc.exe stop Sysmon64`, run RW-01,
  investigate the signal (it will come from Security 4688), then `sc.exe start Sysmon64`.
  Expect the process tree requirement to fail ("no process identity") and the report to be
  incomplete / `insufficient_evidence`. Known limitation: discovery may still show Sysmon
  `active` because older events exist — record what the dashboard shows.

## 3. Capture evidence

```powershell
powershell -ExecutionPolicy Bypass -File docs\validation\v0.3\capture_evidence.ps1 -Hours 3
```

The folder contains `sources.json`, `signals.txt`, the raw channel exports, `host.json` and
the saved reports. It can be replayed anywhere (no Windows needed):

```powershell
python -m investigator --llm mock --backend windows-replay --replay-dir .\rw-evidence-<stamp> list
```

Review it for personal data before sharing it.

## 4. Also confirm

* `Recommendations only — no response actions were executed.` appears on every report.
* No process was killed, no file quarantined, no setting changed by the investigator
  (it has no such capability; see SECURITY.md).
* Record Ollama version, model, `num_ctx`, and each report's `context_overflow_suspected`
  and prompt token counts (in the report's audit trace).
