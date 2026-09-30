> **Superseded in part by [REVIEW.md](REVIEW.md) (v0.2.0).** This file is preserved as the previous review's record; its findings are re-checked in REVIEW.md §1.

# Investigation and improvements — 2026-09-30

The original ZIP is preserved. Changes are in the extracted `soc-investigator` directory.
The baseline ran 63 passing tests and passed all five fixture evaluations. Those checks
did not cover several material security and correctness defects. This remains a local
analyst-assistance MVP, not a production SOC platform or a validated detection model.

## Findings and implemented changes

| Finding | Improvement |
| --- | --- |
| High: activity messages were concatenated into `innerHTML`, including model/telemetry text. | Text-node rendering, external JavaScript, restrictive script CSP; Markdown exports escape untrusted markup. |
| High: generic DNS, network and authentication observations could justify C2, theft, compromise or strong verdicts. | Conservative claim prerequisites, unique evidence counting, time/host/process/account correlation, stronger verdict guards. Rejected or untagged interpretations become factual observations; corrected drafts receive explicit validation notes. |
| High: arbitrary alert IDs entered filesystem paths and download headers. | Application-generated run IDs name atomic report files and downloads. |
| High: repeated web requests could spawn unbounded work. | Concurrent-run limit, duplicate active-run reuse, bounded in-memory history, HTTP 429 on capacity. |
| High: Wazuh `_id` values could collide across daily indexes; partial search results could appear complete. | Opaque index-qualified references, scope-checked exact retrieval, ambiguous legacy-ID rejection, partial/malformed response rejection. |
| Medium: process trees and evidence pivots could use the wrong host or exceed bounds. | Targeted ancestry queries, host-consistent pivots, bounded tree construction, explicit truncation and time-window restrictions. |
| Medium: failed gathering/report generation and disk failures looked successful. | Completed/incomplete/failed assessments, recorded seed errors and budget exhaustion, visible persistence warning, atomic writes. |
| Medium: local browser requests lacked host/origin checks. | Loopback/configured-host allowlist, cross-origin POST checks, no-store/nosniff headers. These do not replace authentication. |
| Medium: CLI health and JSON evaluation returned success on failure; Ollama accepted the wrong model tag as healthy. | Meaningful exit codes, exact model-tag checks, controlled malformed-response handling. |
| Medium: evaluator accepted one failure as multiple logons, ignored required indicators and most missing/unexpected mappings. | Correlated multi-event checks, actual rundll32 execution check, all expected mappings required, unexpected mappings rejected, validation corrections and invalid mapping references fail evaluation. |

## Evaluation corrections

INC-001 originally expected T1204.002 and T1105 from Office ancestry and an external
connection. That telemetry does not establish malicious-file user execution or a
completed tool transfer. Those expectations and mock-model assertions were removed;
PowerShell execution and encoding expectations remain. The mock retains benign
management-script observations without presenting them as adversarial ATT&CK mappings.
These are documented corrections to the benchmark, not evidence of improved LLM accuracy.

## Verification

- Windows / Python 3.12; isolated `.venv`, installed with `pip install -e '.[dev]'`.
- `python -m pytest -q`: **161 passed**.
- `node --test tests/test_activity_dom.cjs`: **3 passed**, including hostile log text and incomplete/disk-failure states.
- `python -m investigator --llm mock --backend fixture evaluate --json`: **5/5 passed**,
  required-evidence recall 1.0, no invalid references or forbidden claims, all expected
  mappings present and no unexpected mappings under the corrected expectations.
- Browser: submitted INC-001 using the keyboard, observed live activity and completed
  report-ready state and opened the completed report. Screenshot: `docs/screenshots/improved_report.png`. HTTP routes, exports, concurrency, persistence and browser-origin
  controls also covered by automated tests.

## Run the improved demo

From this directory in PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\start-demo.ps1
```

Open `http://127.0.0.1:8000`. Use `start-demo.ps1 -Port 8765` for an alternate port.
The source ZIP excludes the virtual environment, credentials, generated reports and caches.

## Remaining limitations

- No real Ollama model or live Wazuh cluster was exercised. HTTP adapters were tested
  with controlled mock transports. Five synthetic cases do not establish SOC accuracy.
- Valid evidence references and structured prerequisites do not verify arbitrary
  narrative, attribution, intent, recommendations or confidence. Analyst review remains necessary.
- Prompt-injection screening is heuristic. Source logs, model text and JSON exports are
  untrusted and can contain sensitive data. Audit prompt/response fields are clipped.
- No authentication, authorization, multi-tenant isolation, cancellation, graceful job
  draining or automatic history restoration. Keep the UI on loopback; wildcard binding
  does not automatically authorize arbitrary Host headers.
- Reports survive on disk but are not automatically reloaded into the dashboard.
  Disk retention is manual. The source distribution expects the included `cases` directory;
  a standalone installed wheel with bundled fixtures has not been validated.
