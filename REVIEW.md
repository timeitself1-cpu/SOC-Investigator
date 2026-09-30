# Independent review and improvement plan — v0.2.0 (2026-09-30)

Source of truth: `soc_investigator_improved.zip` (the "improved" package). It was
committed unmodified as the baseline, and every finding below was reproduced against
it before any change. Reproduction scripts and their outputs are in
`docs/validation/` (`repro_review.py`, `repro_baseline.txt` vs `repro_current.txt`,
`repro_r1b_*`, `bench_baseline.py`, `benchmark_baseline_uploaded_source.txt`).

Environment for this review: Linux, CPython 3.12.3, Node 22, Chromium (Playwright).
The previous review was done on Windows. Neither review had access to a live
Ollama server or a live Wazuh cluster.

## 1. Previous audit's claims, checked

| Claim (AUDIT_AND_IMPROVEMENTS.md) | Result here |
| --- | --- |
| 161 Python tests, 3 JS tests, 5/5 fixture evaluations | **Reproduced** exactly on Linux. |
| Activity feed uses text nodes; Markdown escaped; CSP; Host/Origin checks | **Confirmed** by reading and tests; out-of-process check: foreign Origin → 403, foreign Host → 400. Markdown still allowed structure injection (R12). |
| Weak C2/compromise rules removed; correlated verdict guards | **Confirmed**, but the benign guard could be satisfied by a spoofed or unrelated process (R1, R1b). |
| Rejected/untagged interpretations become observations | **Confirmed.** |
| Bounded concurrency, duplicate-run reuse, atomic persistence | **Confirmed.** No restart recovery, cancellation or shutdown handling, as the audit disclosed (R13). |
| Completed/incomplete/failed distinguished; seed failures and budgets recorded | **Confirmed**, but the rule that made the status "incomplete" also fired on normal Sysmon ancestry gaps (R5). |
| Index-qualified Wazuh refs; partial-search rejection | **Confirmed.** Missing indexes, token expiry and malformed alerts were still unhandled (R6, R7, R9). |
| Corrected INC-001 expectations (drop T1204.002/T1105) | **Agree.** Ancestry plus one outbound connection establishes neither user execution of a malicious file nor a completed transfer. |
| "Audit prompt/response fields are clipped" (listed as a limitation) | **True, and more significant than stated**: the `final_report` prompt was clipped in 4 of 6 INC-004 exchanges, with no structured flag or hash (R3). |

## 2. Findings

Severity reflects impact on a trustworthy real-world investigation, not on the mock demo.

| # | Sev. | Finding | Evidence (code path) | Reproduction (baseline → current) | Status |
| --- | --- | --- | --- | --- | --- |
| R1 | **High** | A benign verdict could be obtained through a masquerading management agent. | `evidence.derive_indicators` matched the parent **basename** only; `report.validate_report` accepted `benign` when `benign_administration` was supported. | `C:\Users\Public\AgentExecutor.exe → powershell -EncodedCommand` → internal host: mock `benign 0.70 completed valid`; model-drafted benign accepted, no issues → now `masquerade_suspect`, claim rejected, verdict withheld. | Fixed · `test_r1_*` |
| R1b | **High** | An unrelated, genuinely managed process on the same host could clear the alert. | The benign guard checked that the claim was supported *anywhere*, not on the alerted process. | `repro_r1b_*`: `benign completed []` → `insufficient_evidence` ("not established for the alerted process itself"). | Fixed · `test_benign_requires_admin_context_on_the_alerted_process_itself` |
| R2 | **High** | Prompts were unbounded relative to the model context. Ollama truncates silently and drops the system prompt first. | `agent._state_block` serialized every evidence item; no `num_predict`. | 150 items → 302,906 chars (~76k tokens) for `num_ctx=16384` → 37,922 chars ≤ 38,240 budget, compaction level 4, 62 items omitted and disclosed. | Fixed · `test_r3_*` |
| R3 | Medium | The audit trace clipped prompts, including `final_report`, with no flag or hash. | `agent._clip(…, 6000)`. | INC-004: 4 of 6 exchanges clipped at 6,011 chars → 0 clipped; every exchange carries prompt/response SHA-256, sizes, budget and omitted counts; any clipping is flagged. | Fixed · `test_r4_*` |
| R4 | Medium | `get_host_context` results never reached the model or the report. | `_state_block` omitted `ToolResult.extra`; the report had no host field. | "SCCM" role text in prompt: False → True; in report: False → True (sanitized, labelled untrusted). | Fixed · `test_r2_*` |
| R5 | Medium | Realistic Sysmon (parent GUID present, parent outside the window) marked every tree "truncated" → `incomplete` → benign unreachable. The demo fixtures omitted the field, which hid this. | `tools.tool_get_process_tree`: `truncated = bool(chain)` when the parent is missing. | INC-005 with a real parent GUID: `insufficient_evidence incomplete` → `benign completed`. Independent suite on baseline: 14/18 reports `incomplete`. | Fixed (ancestry gap = `partial` + known unknown); fixtures made realistic · `test_r5_*` |
| R6 | Medium | A missing archives index looked like "no activity". | `wazuh._search`: a wildcard with no index returns 200, 0 shards, 0 hits. | Returned `[]` → `index_missing` (plus `allow_no_indices=false`; a 404 `index_not_found` is classified too). | Fixed · `test_r6_*`, `test_failure_modes.py` |
| R7 | Medium | The Wazuh API token was cached forever; 401 on expiry. | `wazuh._token`. | Second call → `HTTPStatusError 401` → refreshed once, succeeds. | Fixed · `test_r7_*` |
| R8 | Medium | Raw backend exception text reached the trace, the model prompt and the UI. | `tools.dispatch` used `f"{exc}"`; `RunState.fail` did the same. | Error `…Authorization: Basic dTpw…` → "An unexpected internal error occurred." with `error_kind`. | Fixed (`errors.py`) · `test_r8_*`, service tests |
| R9 | Medium | One malformed alert broke the whole queue; a backend outage gave the queue page a 500. | `wazuh.list_alerts`, `app.index`. | `ValueError` → 1 alert listed + "1 skipped"; the page renders a classified banner. | Fixed · `test_r9_*`, `test_queue_degrades…` |
| R10 | Medium | Identical tool calls were re-run until the step budget ran out. | No duplicate detection (`duplicate` status existed but was unused). | 12 backend queries → 1; three consecutive duplicate/rejected calls end gathering. | Fixed · `test_identical_requests_…` |
| R11 | Low | A raw telemetry key `_role:"trigger"` spoofed the trigger marker. | `agent` stored the marker in `Evidence.raw`. | Spoofed record `is_trigger=True` → False (the marker is application-owned). | Fixed · `test_r11_*` |
| R12 | Low | Model prose could create Markdown headings, rules or code blocks; a latent `m` shadowing bug. | `report._markdown_text` did not escape `=` or line structure. | `===` / indented lines → escaped and collapsed. | Fixed · `test_r12_*` |
| R13 | Medium | No durable history, restart recovery, cancellation or graceful shutdown. | `service.py` was in-memory; threads were daemons. | Journal + replay (`interrupted` on crash), cancel route, shutdown with grace period; verified out-of-process with the installed wheel (SIGTERM → restart → history + report 200). | Implemented · `test_reliability_and_reporting.py`, `wheel_restart_check.txt` |
| R14 | Medium | A wheel install could not run: cases missing, reports written into site-packages. | `config.PROJECT_ROOT/"cases"`. | `FileNotFoundError` → packaged cases and benchmark; reports under `%LOCALAPPDATA%` / XDG. | Fixed · `test_r15_*`; clean wheel install verified |
| R15 | Medium | Evaluation used only the five authored fixtures and a single pass/fail; a missing-trigger alert crashed the loader. | `fixture._load` indexed `events[event_ref]`. | Independent suite on baseline: X05 `KeyError`; M01 kept a forbidden `benign_administration` claim. | Independent suite + separated metrics · `test_benchmark.py` |
| R16 | Low | Model output was unbounded and a truncated JSON answer was indistinguishable from malformed output. | No `num_predict`; `done_reason` ignored. | `done_reason=length` → rejected with a specific error, repaired visibly (`model_output_repairs`). JSON-schema `format` sent when supported. | Fixed · `test_output_cut_off…`, `test_ollama_payload…` |
| R17 | Low | Model argument mistakes (rejected calls) marked collection "incomplete", conflating model errors with telemetry gaps. | `report.collection_incomplete` included `rejected`. | Rejected calls are now counted as `coverage.rejected` and disclosed as unknowns; status is unchanged. **Deliberate semantic change.** | Changed · `test_rejected_model_request_is_disclosed…` |
| R18 | Low | *Found in my own new code during this pass:* the run status was published before its journal record was written, so a crash in that window restored a finished run as "interrupted". | `service._run` (v0.2 draft). | Flaky full-suite test → deterministic ordering test. | Fixed before release · `test_final_journal_is_durable_before_status_is_published` |

Not fixed (disclosed): confidence is uncalibrated; prompt-injection screening is
heuristic; there are no signer/hash fields, so a path check cannot prove a binary
is genuine; cancellation is cooperative (a request in flight finishes within its
timeout); a single tool call (e.g. a 16-ancestor Wazuh tree walk) can overrun the
time budget, which is only checked between steps; the journal is not safe for two
server processes sharing one reports directory.

## 3. Prioritized plan and status

| Pri | Item | Status |
| --- | --- | --- |
| P0 | Fix R1/R1b benign guard (install path, trigger-bound, contradictions, injection) | **Done, tested** |
| P0 | Collection coverage ledger: scope/outcome/gaps per call, status from ledger, unknowns, backend caveats | **Done, tested** |
| P0 | Separate observed facts / hypotheses / verification steps / unverified narrative (JSON, HTML, Markdown) | **Done, tested** |
| P0 | Classified, redacted errors; Wazuh missing index, 401 refresh, malformed alerts | **Done, tested** (mock transports) |
| P0 | Opt-in live integration tests (Ollama and Wazuh: auth, TLS, permission, missing archives, mapping, timeouts, incomplete telemetry) + `diagnose` CLI | **Harness implemented; not run live** (no services reachable here) |
| P1 | Independent benchmark (18 cases) with ground truth committed before any run; separated metrics | **Done**; results below |
| P1 | Context budget + recorded compaction; `num_predict`; schema `format`; `done_reason`; audit hashes | **Done, tested** (chars/token ratio unverified on a real tokenizer; the live test measures it) |
| P1 | Durable history, restart recovery, cancellation, graceful shutdown, time budget | **Done, tested** (incl. out-of-process restart) |
| P2 | Evidence filters/anchors, rerun, history page, partial-result explanations | **Done**, verified in real Chromium |
| P2 | Packaged fixtures/benchmark; clean wheel install | **Done**, verified in a fresh venv |
| Next | Run the live suites in a lab; benchmark real models; third-party-authored cases; signer/hash enrichment for management agents; per-tool deadlines | Proposed |

## 4. Benchmark results (mock model — pipeline measurement, not LLM accuracy)

`python -m investigator --llm mock benchmark` (full output: `docs/validation/benchmark_mock.txt`):

| Metric | Current | Baseline (same suite) |
| --- | --- | --- |
| Harness errors | 0 | 1 (X05 missing trigger → `KeyError`) |
| Forbidden verdicts | 0 | 0 |
| Retained forbidden claims | 0 | 1 (M01 `benign_administration` on a masquerade) |
| Escalation threshold TP/FN/FP/TN | 7/0/1/5 (FPR 0.167, FNR 0.0) | — |
| Strict threshold (likely_malicious) FNR / FPR | 0.429 / 0.0 | — |
| Benign cleared | 1 of 6 (0.167) | 0 of 6 |
| Reports `incomplete` | 2 (X05 missing trigger, X07 truncation — both expected) | 14 |
| Evidence recall, retrieved / cited | 0.971 / 0.833 | — |

Interpretation: the guards and pipeline behave safely. The system is conservative
(it rarely clears benign activity, and the vendor-updater case escalated as
suspicious), and noise-driven truncation hid one required record in X07 (disclosed,
as that case's truth requires). No ground truth was changed after these runs. The
mock model was not tuned to the suite.
