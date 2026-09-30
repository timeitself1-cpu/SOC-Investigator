# Current validation — 2026-09-30

The improved source passes **161 Python tests** and **5/5 fixture evaluations** on
Windows/Python 3.12. See [AUDIT_AND_IMPROVEMENTS.md](AUDIT_AND_IMPROVEMENTS.md) for
commands, scope, benchmark corrections and limitations. Browser submission and live
activity were checked. Ollama and Wazuh remain **not live-verified**.

The material below was supplied in the original ZIP. It is preserved as a historical
record of the original author's claims; it is not the current review's test output.

---

# Validation

This file records the acceptance-gate commands that were **actually executed** and
their **actual output**, before packaging. Each item is labeled:

- **VERIFIED** — run here, output reproduced below.
- **IMPLEMENTED BUT NOT LIVE-VERIFIED** — code exists and is unit-tested, but not
  run against the real external system.
- **NOT IMPLEMENTED** — explicitly out of scope.

Environment used for this run: Linux, CPython **3.12.3**, dependencies from
`requirements.txt` (FastAPI 0.142.1, Pydantic 2.13.5, Uvicorn 0.54.0, httpx 0.28.1,
Jinja2 3.1). A clean `python3.12 -m venv` + `pip install -r requirements.txt` in an
empty environment was verified to install and pass the suite with no other packages.

> Reproduce on Windows with the same commands (PowerShell) shown in the README.
> The mock+fixture path requires neither Ollama nor Wazuh.

---

## 1. Test suite — VERIFIED

Command:
```
python -m pytest -q
```
Actual result:
```
...............................................................          [100%]
63 passed in 1.60s
```
63 tests across 9 test files, covering: schema validation, evidence-reference
enforcement, invalid evidence IDs, tool allowlisting, tool argument validation,
bounded event results, maximum investigation iterations, malformed LLM output +
repair/fallback, model-error resilience, FixtureBackend behavior, process-tree
reconstruction, evaluation scoring, JSON/Markdown export, telemetry
prompt-injection handling, WazuhBackend query construction / read-only guard /
normalization (mocked transport), and "no remediation capability exposed".

Clean-install check (empty venv, only `requirements.txt`): `63 passed`.

## 2. All five fixture investigations with the mock model — VERIFIED

Command (per case):
```
python -m investigator --llm mock investigate INC-00N
```
Actual results:
```
INC-001  Verdict: likely_malicious (0.90)  Findings: 2  Evidence: 5  Tool calls: 7  Valid: True  ATT&CK: T1027, T1059.001, T1105, T1204.002
INC-002  Verdict: likely_malicious (0.90)  Findings: 1  Evidence: 4  Tool calls: 7  Valid: True  ATT&CK: T1003.001
INC-003  Verdict: likely_malicious (0.80)  Findings: 1  Evidence: 4  Tool calls: 7  Valid: True  ATT&CK: T1053.005, T1547.001
INC-004  Verdict: likely_malicious (0.90)  Findings: 2  Evidence: 9  Tool calls: 5  Valid: True  ATT&CK: T1078, T1110
INC-005  Verdict: benign          (0.70)  Findings: 3  Evidence: 3  Tool calls: 7  Valid: True  ATT&CK: T1027, T1059.001
```
INC-005 (the benign look-alike) is correctly **not** `likely_malicious`.

## 3. Evaluator — VERIFIED

Command:
```
python -m investigator --llm mock evaluate
```
Actual result:
```
Evaluation: 5/5 passed  (pass_rate=1.0, mean_recall=1.0, invalid_refs=0, forbidden_claims=0)

  PASS  INC-001   verdict=likely_malicious     recall=1.0 tools=7 findings=2
  PASS  INC-002   verdict=likely_malicious     recall=1.0 tools=7 findings=1
  PASS  INC-003   verdict=likely_malicious     recall=1.0 tools=7 findings=1
  PASS  INC-004   verdict=likely_malicious     recall=1.0 tools=5 findings=2
  PASS  INC-005   verdict=benign               recall=1.0 tools=7 findings=3
```

## 4. Every finding references valid evidence — VERIFIED

For all five cases, every `finding.evidence_ids` entry is present in that report's
retrieved evidence set; `validation.invalid_evidence_refs` is empty in all cases:
```
INC-001: findings_cite_only_real_evidence=True  invalid_refs=[]
INC-002: findings_cite_only_real_evidence=True  invalid_refs=[]
INC-003: findings_cite_only_real_evidence=True  invalid_refs=[]
INC-004: findings_cite_only_real_evidence=True  invalid_refs=[]
INC-005: findings_cite_only_real_evidence=True  invalid_refs=[]
ALL FINDINGS REFERENCE VALID EVIDENCE: True
```
The negative case (a fabricated `EV-9999` reference is dropped, and a bogus-only
finding causes a verdict downgrade) is covered by
`tests/test_report_validation.py`.

## 5. No remediation / execution capability exists — VERIFIED

```
tool names: ['get_host_context', 'get_network_activity', 'get_process_details',
             'get_process_tree', 'get_related_events', 'search_events']
banned-substring tools: []            # none of execute/run/shell/write/http/ssh/kill/...
allowlist is exactly the 6 read-only tools: True
```
`RecommendedAction.executed` is typed `Literal[False]`; a test asserts an executed
action cannot be constructed. The Wazuh HTTP layer additionally rejects any request
outside its `(target, method, path)` allowlist (tested).

## 6. Web application starts and serves — VERIFIED

Exercised via FastAPI's `TestClient` (starts the ASGI app in-process):
```
GET /healthz: {'status': 'ok', 'llm': 'mock', 'backend': 'fixture', 'model': 'mock-analyst', 'max_steps': 12}
GET / :       200   queue-rendered: True
POST /investigate/INC-001 -> background run -> status: completed
```
`python -m investigator serve` was also confirmed to boot Uvicorn and bind the port
during screenshot capture (see `docs/screenshots/`).

## 7. JSON export — VERIFIED

```
GET /export/{run}.json : 200, parses as JSON, contains investigation_id
```

## 8. Markdown export — VERIFIED

```
GET /export/{run}.md : 200, contains "# Investigation" header and the
"no response actions were executed" notice
```

---

## Component status summary

| Capability | Status |
| --- | --- |
| Core data model + strict validation | **VERIFIED** |
| Evidence store owns IDs; sanitization; injection screening | **VERIFIED** |
| Six bounded read-only tools; allowlist; arg validation; result/window bounds | **VERIFIED** |
| Bounded agent loop; malformed-output repair + fallback; model-error resilience | **VERIFIED** |
| Report validation (drops fabricated evidence, unsupported claims/ATT&CK; verdict guard) | **VERIFIED** |
| Evaluator (recall, forbidden claims, ref validity, verdict, completion, tool count) | **VERIFIED** |
| FixtureBackend + 5 incidents incl. benign look-alike | **VERIFIED** |
| Mock model end-to-end (demo + tests) | **VERIFIED** |
| Web UI: queue / live investigation / report / JSON + Markdown export | **VERIFIED** |
| CLI: serve / list / investigate / evaluate / health | **VERIFIED** |
| **Ollama** client (`/api/chat`, `format=json`, health check) | **IMPLEMENTED BUT NOT LIVE-VERIFIED** — not run against a live Ollama here; the mock model exercises the identical agent path. Run `python -m investigator health` after `ollama serve`. |
| **Wazuh** backend (indexer `_search`, server API, read-only guard, normalization) | **IMPLEMENTED BUT NOT LIVE-VERIFIED** — query construction, read-only allowlist, and normalization are unit-tested with a mocked HTTP transport; not run against a live Wazuh cluster. Index names, Sysmon field mappings, and TLS/auth must be confirmed in your lab (see README "Wazuh configuration"). |
| Multi-agent orchestration, autonomous remediation, shell/command execution, Docker/K8s, cloud deps, external LLM APIs, vector DB, auth/RBAC | **NOT IMPLEMENTED** — intentionally out of scope per the MVP requirements. |

## Honesty notes

- The two integrations above (Ollama, Wazuh) are **not** claimed to be verified
  against their live systems. Their code paths are exercised by unit tests using
  mocks/stand-ins; the fixture + mock path is what is fully verified end-to-end.
- The mock model is a deterministic rule-based analyst, not a language model. It
  demonstrates and tests the *pipeline and its guarantees*; qualitative analytic
  judgment comes from running Mode 2/3 with a real local model.
