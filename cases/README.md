# Fixture cases

Each `INCxxx/` directory is a self-contained incident:

- `events.json` — Wazuh-shaped telemetry documents (`data.win.system` /
  `data.win.eventdata`), normalized by the same code the live Wazuh backend uses.
- `alert.json` — the alert metadata (`alert_id`, `title`, `severity`, and the
  `event_ref` of the triggering event).
- `hosts.json` — asset/role/criticality context returned by `get_host_context`.
- `expectations.json` — machine-readable grading criteria for the evaluator
  (`required_evidence`, `acceptable_verdicts`, `forbidden_claims`,
  `expected_attack`, `min_tool_calls`).

Regenerate all of them with `python build_fixtures.py` from the project root.

| ID | Scenario |
| --- | --- |
| INC-001 | WINWORD → encoded PowerShell → outbound C2 (malicious document) |
| INC-002 | comsvcs.dll MiniDump of LSASS (credential dumping) |
| INC-003 | Scheduled task + Run-key persistence |
| INC-004 | Brute force (many 4625) → successful logon (4624) from an external IP |
| INC-005 | BENIGN: SCCM inventory — encoded PowerShell as SYSTEM to an internal host |
