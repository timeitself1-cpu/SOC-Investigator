# Validation — v0.3.1 (reasoning-contract repair, 2026-09-30)

Same environment as v0.3.0 below: Linux x86-64, CPython 3.12.3 pinned venv, Node 22,
Chromium; Qwen2.5 tokenizer from npm `@lenml/tokenizer-qwen2_5`. **No Ollama, no
Windows host.** Raw outputs: [`docs/validation/v0.3.1/`](docs/validation/v0.3.1/).
Every row except 13 and 14 is reproduced by `docs/validation/v0.3.1/run_validation.sh`.
Summary: [V0.3.1_RELEASE_NOTES.md](V0.3.1_RELEASE_NOTES.md).

| # | Command | Result | Output file |
| --- | --- | --- | --- |
| 1 | `python -m pytest -q` ×5 | 356 passed, 4 skipped, 19 deselected — every run | `pytest.txt`, `pytest_5x.txt` |
| 2 | `pytest tests/test_browser_ui.py -m ""` (Chromium) | 2 passed | `pytest_browser.txt` |
| 3 | `node --test tests/test_activity_dom.cjs` | 6 passed | `node_dom_tests.txt` |
| 4 | `pytest -m integration` (unconfigured) | 19 skipped | `pytest_integration_unconfigured.txt` |
| 5 | `python -m investigator --llm mock benchmark` | benign FP 0, TP 9/9; contract: 0 invalid args, 0 duplicates, 0 loop stops, 6 revisions | `benchmark_mock.txt/.json` |
| 6 | `… benchmark --adversary benign-after-investigation / benign-immediately` | benign FP **0** / **0** | `benchmark_benign-*.txt/.json` |
| 7 | `python -m investigator --llm mock acceptance` | ALL CRITERIA PASSED | `acceptance_mock.txt` |
| 8 | `python -m investigator --llm mock evaluate` | 5/5 | `evaluate_demo.txt` |
| 9 | `python docs/validation/v0.2.1/final_gate.py . <tokenizer.json>` | 9/9 (A–G) | `final_gate_v021_on_v031.txt` |
| 10 | `python docs/validation/v0.3/replay_e2e.py` (SYNTHETIC XML) | verdicts and statuses identical to v0.3; only tool order changed (baseline tree first) | `replay_synthetic_e2e.txt` |
| 11 | `probe_tokens.py` (floods) and `probe_contract_tokens.py` (all prompts incl. revision, 16384 and 8192) | no overflow; max 9,956 / 8,829 tokens at 16384, 2,758 at 8192 | `tokens_16384_floods.txt`, `tokens_contract.txt` |
| 12 | mutation sets v0.2.1 / v0.3 / v0.3.1 | 11/11, 10/10, 11/11 killed (C4 and C10 survived the first v0.3.1 run; tests added) | `mutation_*.txt` |
| 13 | `scripted_replay.py` (observed qwen behaviour, scripted) | ignore-feedback model contained (0/7, no false benign); feedback-following model 7/7 | `scripted_replay.txt` |
| 14 | visibility defect impact, v0.3 vs v0.3.1 at 8192 | v0.3: BM-B01, BM-B05 benign with tree records unseen; v0.3.1: none; adversary benign FP 0 in both | `visibility_defect_impact.txt`, `visibility_defect_counts.txt` |

**NOT VERIFIED:** v0.3.1 with a real model. `run_ollama_eval.sh` / `.ps1` have not been
run; see `ollama_before_after.md`. Live Windows reader and RW-01…RW-05, Windows channel
permissions and Wazuh are also not verified.

---

# Historical: validation — v0.3.0 (standalone Windows investigator, 2026-09-30)

Executed on Linux x86-64, CPython 3.12.3 (`.venv`: pinned `requirements-validated.txt`,
`pip install -e '.[dev]'`, `playwright`, `tokenizers`), Node v22.22.2, Chromium 1194.
**No Windows host and no Ollama were available.** Raw outputs:
[`docs/validation/v0.3/`](docs/validation/v0.3/); summary with VERIFIED / NOT VERIFIED:
[V0.3_RELEASE_NOTES.md](V0.3_RELEASE_NOTES.md).

| # | Command | Result | Output file |
| --- | --- | --- | --- |
| 1 | `python -m pytest -q` ×5 | 328 passed, 4 skipped, 19 deselected — every run | `pytest_5x.txt` |
| 2 | `SOCI_TOKENIZER_JSON=… pytest tests/test_integrity_v021.py tests/test_windows_backend.py tests/test_v03_requirements.py` | 103 passed | `pytest_5x.txt` |
| 3 | `pytest tests/test_windows_backend.py tests/test_v03_requirements.py` (Windows backend unit tests) | 47 passed | `pytest_5x.txt` |
| 4 | `node --test tests/test_activity_dom.cjs` | 6 passed | `node_dom_tests.txt` |
| 5 | `python -m investigator --llm mock --backend fixture evaluate` | 5/5 | `evaluate_demo.txt` |
| 6 | `python -m investigator --llm mock benchmark [--adversary …]` | benign FP 0 in all three; exit 0 | `benchmark_*.txt/.json` |
| 7 | `python docs/validation/v0.2.1/final_gate.py . <tokenizer.json>` | 9/9 | `final_gate_v021_on_v03.txt` |
| 8 | `python docs/validation/v0.3/replay_e2e.py` (SYNTHETIC Windows XML) | see file | `replay_synthetic_e2e.txt` |
| 9 | `python -m investigator --backend windows-replay [--replay-dir …] sources` | demo all ✓ (exit 0); no-Sysmon host ○ Sysmon (exit 2) | `sources_replay_*.txt` |
| 10 | `python -m investigator --backend windows sources` on Linux | classified failure, exit 1 | `sources_live_on_linux.txt` |
| 11 | `PY=… docs/validation/v0.3/mutate_v03.sh . <scratch>` | 10/10 dedicated tests fail under mutation | `mutation_output.txt` |
| 12 | `PY=… docs/validation/v0.2.1/mutate_v021.sh . <scratch>` (on 0.3.0) | 11/11 | `mutation_v021_rerun.txt` |
| 13 | `python docs/validation/followup/probe_tokens.py . <tokenizer.json>` | no overflow; max 10,017 tokens | `tokens.txt` |
| 14 | wheel → fresh venv → unrelated dir → `sources/list/investigate/evaluate` | 0.3.0 works | `packaging_restart.txt` |
| 15 | installed `serve` (windows-replay) → 2 runs → SIGTERM → new process | both restored | `packaging_restart.txt` |
| 16 | `pytest -m integration tests/integration -rs` (+ `SOCI_IT_WINDOWS=1`) | 19 skipped (no Ollama, no Wazuh, not Windows) | `pytest_integration.txt` |

**NOT VERIFIED:** the live Windows event log reader; RW-01…RW-05 on a real machine
(`docs/validation/v0.3/RESULTS.md` — NOT RUN); Windows channel permissions; Ollama;
Wazuh.

---

# Historical: validation — v0.2.1 (Investigation Integrity Fix, 2026-09-30)

Executed in this pass on Linux x86-64, CPython 3.12.3 (`.venv`, pinned
`requirements-validated.txt` + `pip install -e '.[dev]'` + `playwright` for the
browser tests + `tokenizers` for the optional real-tokenizer tests), Node v22.22.2,
Chromium 1194. Raw outputs are in [`docs/validation/v0.2.1/`](docs/validation/v0.2.1/);
the summary table is in [V0.2.1_RELEASE_NOTES.md](V0.2.1_RELEASE_NOTES.md).

| # | Command | Result | Output file |
| --- | --- | --- | --- |
| 1 | `python -m pytest -q` ×5 | 279 passed, 4 skipped, 15 deselected — every run | `pytest_5x.txt` |
| 1b | `SOCI_TOKENIZER_JSON=<Qwen2.5 tokenizer.json> python -m pytest -q tests/test_integrity_v021.py` | 55 passed | `pytest_5x.txt` |
| 2 | `node --test tests/test_activity_dom.cjs` | 6 passed | `node_dom_tests.txt` |
| 3 | `python -m investigator --llm mock --backend fixture evaluate [--json]` | 5/5 passed | `evaluate_demo.txt/.json` |
| 4 | `python -m investigator --llm mock benchmark [--adversary …] --out …` | see release notes; benign FP 0 in all three runs | `benchmark_*.txt/.json` |
| 5 | `python docs/validation/v0.2.1/final_gate.py . <tokenizer.json>` | 9/9 | `final_gate_output.txt` |
| 5b | `python docs/validation/followup/probe_{benign,gate,hostctx,window,cancel,tokens}.py .` | every follow-up finding reversed | `followup_probes_after.txt`, `tokens_after.txt` |
| 6 | `PY=… docs/validation/v0.2.1/mutate_v021.sh . <scratch>` | 11/11 dedicated tests fail under their mutant | `mutation_output.txt` |
| 6b | `PY=… docs/validation/followup/mutate.sh . <scratch>` | R1–R18 set: killed except 2 known equivalent mutants | `mutation_r1_r18_rerun.txt` |
| 7–9 | `pip wheel --no-deps`; fresh venv; `investigator list/evaluate/benchmark` from an unrelated dir | 0.2.1 installed and working | `packaging_restart.txt` |
| 10 | installed `investigator serve` → 2 investigations → SIGTERM → new process | both runs restored, report/export 200 | `packaging_restart.txt` |
| — | `python -m pytest -m integration tests/integration -rs` | 15 collected, 15 skipped (no Ollama, no Wazuh) | `pytest_integration_unconfigured.txt` |

**Ollama: NOT VERIFIED** (not installed or reachable here). **Wazuh: NOT VERIFIED**
(no cluster). Not re-run on Windows in this pass.

---

# Historical: validation — v0.2.0 (2026-09-30)

Everything in this section was **executed in this pass** and the exact outputs are
saved in `docs/validation/`. Sections further below are historical records from
earlier packages and are not re-verified claims.

Environment: Linux x86-64, CPython 3.12.3 (`.venv`, `pip install -e '.[dev]'`),
Node v22.22.2, Chromium 1194 via Playwright (browser tests only). **Not re-run on
Windows in this pass**; the PowerShell instructions are unchanged from the verified
Windows run in the previous review.

## VERIFIED (executed here)

| Command | Result | Output |
| --- | --- | --- |
| `python -m pytest -q` | **228 passed**, 15 deselected (opt-in integration), 0 failed | `pytest_default.txt` |
| same, repeated | 5 consecutive full runs green (228 passed each) after the final fix; the browser test file alone 15/15 green. Two intermittent failures were found and fixed on the way: a real journal/status race (R18) and a test-harness wait that the CSP correctly blocked | — |
| `node --test tests/test_activity_dom.cjs` | **6 passed** | `node_dom_tests.txt` |
| `python -m pytest -m integration tests/integration -rs` | 15 collected, **15 skipped** (no `SOCI_IT_*` set) — the harness imports and gates correctly; nothing live was exercised | `pytest_integration_unconfigured.txt` |
| `python -m investigator --llm mock --backend fixture evaluate --json` | 5/5 demo fixtures pass (recall 1.0, 0 invalid refs, 0 forbidden claims), with fixtures now carrying realistic parent GUIDs | `evaluate_demo.json` |
| `python -m investigator --llm mock benchmark` | 18 cases; 0 harness errors, 0 forbidden verdicts, 0 retained forbidden claims; escalation FPR 0.167 / FNR 0.0; strict FNR 0.429; benign cleared 1/6; recall 0.971 retrieved / 0.833 cited | `benchmark_mock.txt`, `benchmark_mock.json` |
| Same suite against the **uploaded baseline** | 17/18 acceptable; X05 harness `KeyError`; M01 retained forbidden `benign_administration`; 14/18 reports `incomplete` | `benchmark_baseline_uploaded_source.txt` |
| Review reproductions R1–R11 on baseline vs current | every reproduced defect resolved (diff of the two outputs) | `repro_baseline.txt`, `repro_current.txt`, `repro_r1b_*.txt` |
| Wheel build + install into a fresh venv, run from an unrelated directory | `list`, `evaluate`, `benchmark`, `diagnose` work; packaged cases/benchmark present; reports under the per-user data dir, not site-packages | (commands in REVIEW.md, R14) |
| Installed wheel, out of process: serve → investigate → SIGTERM → restart | run journaled; restored in `/history`; `/report/<run>` 200 after restart; foreign-Origin POST 403; foreign Host 400 | `wheel_restart_check.txt` |
| Real Chromium: queue → Investigate → live activity → report; evidence filters, anchors, cancel, history | pass; external scripts run under `script-src 'self'`; string-`eval` automation is refused by the CSP | `tests/test_browser_ui.py`, `docs/screenshots/v2_*.png` |

## IMPLEMENTED BUT NOT LIVE-VERIFIED

| Capability | What *is* tested | What is not |
| --- | --- | --- |
| Ollama client: `num_predict`, JSON-schema `format`, `done_reason`, classified errors, exact tag health check | payloads, error classification and truncation handling with mock transports / stand-in models | a real Ollama server; whether your Ollama version accepts the Pydantic schemas (fallback: `SOCI_OLLAMA_STRUCTURED_OUTPUT=false`); the real chars-per-token ratio (the live test measures it) |
| Wazuh backend: read-only allowlist, missing-index detection, 401 token refresh, malformed-alert skipping, classified auth/permission/TLS/timeout/mapping/partial errors, `probe()`/`diagnose` | all of the above through the real HTTP code with mock transports (`test_failure_modes.py`, `test_wazuh.py`, `test_review_regressions.py`) | a real indexer/API: index names, field mappings for your Sysmon config, real TLS/auth/permission behaviour, archives |
| Opt-in live suites `tests/integration/` (15 tests) | they collect and skip cleanly | none executed |
| Real-model investigation quality | — | no real model was run; all verdict metrics above are for the rule-based mock |

## NOT IMPLEMENTED (by design or deferred)

Authentication/authorization, multi-tenant isolation, autonomous remediation, shell
execution, external data transmission, multi-process-safe journaling, per-tool
deadlines, signer/hash enrichment, calibrated confidence.

---

# Historical: previous review's validation (2026-09-30, Windows)

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
