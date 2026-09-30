# Follow-up verification of v0.2.0 (2026-09-30)

Scope: `soc_investigator_v0.2.0.zip`, checked against the prior audit in [REVIEW.md](REVIEW.md) (R1–R18).
The zip's own git history (baseline `7aa1fb1` → `d1da6a7`) is preserved in this branch, so each
claim can be diffed against the uploaded baseline. All probe scripts and their raw outputs are in
[`docs/validation/followup/`](docs/validation/followup/).

Environment: Linux, CPython 3.12.3, pinned `requirements-validated.txt`, Node 22, Chromium 1194
(Playwright). As in both earlier reviews, no live Ollama or Wazuh was reachable.

**Bottom line.** The recorded results all reproduce. Every R1–R18 fix is present and behaves as
described on the cases the prior review tested. I found no regression, meaning nothing that worked in the
baseline now fails. Probing beyond those cases turned up three high-severity gaps:

1. The benign-verdict guard still has holes that do not depend on masquerading.
2. The context-budget fix (R2) under-counts tokens for the base64/hex telemetry this tool is built to
   investigate.
3. The R4 change added host context to the prompt without adding a matching guard for it.

## 1. Reproduction of the recorded gate results

| Recorded claim | Result here |
| --- | --- |
| `pytest -q`: 228 passed, 5 consecutive green runs | **Reproduced**: 228 passed ×5. Without Playwright (which `.[dev]` does not install), the result is 226 passed, 1 skipped. |
| `node --test tests/test_activity_dom.cjs`: 6 passed | **Reproduced.** |
| `evaluate --json`: 5/5 | **Reproduced**; only `runtime_ms` differs. |
| `benchmark` (mock) | **Reproduced**: every line identical except the suite path. |
| `repro_review.py` baseline vs current | **Reproduced byte-for-byte** on both trees, as was `repro_r1b_*` (the scripts need `<root> <tmpdir>` arguments, which are not documented). |
| Wheel install from an unrelated directory | **Reproduced**: `list`, `evaluate` and `benchmark` work, and reports go to `$XDG_DATA_HOME`. |
| Out-of-process serve → SIGTERM → restart | **Reproduced** in a new process: `recovered=True`, `/history` lists the run, `/report` and `.md` return 200, a foreign Origin gets 403 and a foreign Host gets 400. |

## 2. Claimed fixes, verified

In the mutation column, "killed" means that reverting the fix makes at least one test fail. Output is in
`mutation_output.txt` (22 mutants: 18 killed, 2 equivalent, 2 surviving).

| # | Verdict | Evidence | Mutation |
| --- | --- | --- | --- |
| R1 masquerade | **Fixed** (see F1, F2, F4) | repro; path check | killed. The `..` traversal check **survives** (untested, F6). |
| R1b unrelated admin | **Fixed** | repro | killed |
| R2 context budget | **Partially fixed** (F3) | chars stay under budget; real tokens do not | killed |
| R3 audit clipping | **Fixed** | repro, 0 clipped | killed |
| R4 host context | **Fixed**, but opens F4 | repro | killed |
| R5 ancestry gap | **Fixed** | repro | killed |
| R6 missing index | **Fixed** (mock transport) | repro | killed |
| R7 token refresh | **Fixed** (mock transport) | repro | killed |
| R8 redaction | **Fixed** | repro; reviewed all `safe_error` paths | killed |
| R9 malformed alert | **Fixed** | repro | killed |
| R10 duplicates | **Fixed** | repro | both mutants killed |
| R11 trigger spoof | **Fixed** | repro | killed |
| R12 Markdown | **Fixed** | review | the `=` mutant is equivalent (newline collapsing already prevents setext headings) |
| R13 durability | **Fixed** | out-of-process restart | — (cancel caveat: F7) |
| R14 packaging | **Fixed** | clean wheel install | — |
| R15 benchmark | **Fixed** (0 harness errors) | benchmark | — (metric caveat: F9) |
| R16 `done_reason` | **Fixed** (mock transport) | tests | killed |
| R17 rejected ≠ incomplete | **As described** (deliberate); widens F1 | — | killed |
| R18 journal race | **Fixed** | 5 green runs | killed |

The masquerade tree-contradiction entry is the second equivalent mutant, because `masquerade_suspect`
is also a host-level contradiction.

## 3. New findings

Severity uses the prior review's scale: impact on a trustworthy real-world investigation.

| # | Sev. | Finding | Reproduction | Regression? |
| --- | --- | --- | --- | --- |
| F1 | **High** | **A benign verdict needs no collection.** A model can call `finish` at step 1 and draft `benign` with `benign_administration` citing the trigger. The report comes back `benign 0.80, completed, valid=True` even though its own ledger lists "Network/DNS activity was not queried" and "Process ancestry … was not reconstructed". Known unknowns are displayed but never gate the verdict. | `probe_benign.py` P1 | Pre-existing |
| F2 | **High** | **Benign contradictions only cover the trigger and its direct children.** In the test, a grandchild (`cmd → rundll32` from `ProgramData`) connects to a public IP. The model retrieved that connection, and `external_destination` is in the evidence, but the benign verdict still stands (`valid=True`). `external_destination` and `user_writable_path` are tree-only contradictions, and `_in_tree` is one level deep. The mock analyst calls the same data `suspicious` (P3), so the guard is the only thing standing between a wrong or injected model and a benign verdict. | `probe_benign.py` P2/P3 | Pre-existing |
| F3 | **High** | **R2's 3.0 chars/token is not conservative for this data.** Measured with the real Qwen2.5 tokenizer (the default model): encoded PowerShell runs at 2.5 chars/token, hex blobs at 2.1 and random base64 at 1.7. Budgeted prompts need 17.1k–24.2k tokens against `num_ctx` 16,384, so Ollama's silent truncation (the R2 defect) comes back. The review's repro filler (`"x"*900`) tokenizes at 3.1, which hid this. `context_overflow_suspected` is only a badge: it changes neither status nor verdict. The content is attacker-controlled, so it can be used to push instructions out of context deliberately. Separately unverified: whether Ollama's `prompt_eval_count` excludes KV-cached prefix tokens, which would weaken the overflow check. | `probe_tokens.py`, `tokens_output.txt` | Pre-existing; the R2 fix is incomplete |
| F4 | Medium | **Injection text in host context does not block benign.** The same text in evidence sets `injection_suspected`, which blocks benign. In host context it only adds a known unknown, and the result is `benign completed valid=True`. R4 made this text visible to the model. Wazuh `os` fields are read from the endpoint by its agent, so an attacker with admin rights on the host can influence them. | `probe_hostctx.py` | **New surface from R4** |
| F5 | Medium | **Result caps keep the oldest events.** Both backends sort by `timestamp asc` and then cap. With 40 routine events in the 15 minutes before the trigger, `get_related_events` returns 25 events that all precede it; the C2 connection 5 s after the trigger is dropped. The status is honestly `incomplete`, but the most relevant records are the ones lost. This is the root cause of BM-X07's missed record. | `probe_window.py` | Pre-existing |
| F6 | Medium | **Two load-bearing safety checks have no test.** First, the "benign withheld when collection is incomplete" gate in `validate_report`: removing it passes all 228 tests, yet with the gate removed a benign draft plus a failed query yields `benign incomplete`. Second, the `..` check in `management_parent_status`: without it, `C:\Program Files\Microsoft Configuration Manager\..\..\Users\Public\AgentExecutor.exe` becomes `trusted_path`. | `mutation_output.txt`, `probe_gate.py` | Test gap |
| F7 | Low | **Cancellation is dropped during the final-report call.** It is accepted (`cancel` → True, and the UI says "stopping after the current step"), but the run finishes `completed/likely_malicious` with no trace that cancellation was requested. | `probe_cancel.py` | New (R13) |
| F8 | Low | **Fixture semantics differ from Wazuh semantics.** Fixture host and GUID matching is case-insensitive, while Wazuh uses exact `term` queries on `agent.name` and `processGuid`. Tests pass on behaviour the live backend does not share. | Code review | Pre-existing |
| F9 | Low | **The benchmark headline "fully correct: 18/18" says little.** Every benign and malicious case accepts `suspicious`, so a constant-`suspicious` policy scores 17/18. The separated metrics (FPR 0.167, 1/6 benign cleared) are the informative ones. The suite is held out from the demo fixtures, but its author also wrote the guards and the mock, so it is not third-party. | `truth.json` files | Reporting |
| F10 | Low | **Validation hygiene.** The 228 count needs Playwright, which is not in `.[dev]`. `test_browser_ui.py` rewrites tracked screenshots on every run. The repro scripts' arguments are undocumented. | — | Reporting |
| F11 | Low | **Shutdown race (by inspection only; not reproduced).** `shutdown()` reads `run.status` outside the lock. A run that finishes in that window can be re-labelled `interrupted` even though its report was saved. | `service.py` `shutdown` | New (R13) |

## 4. Remaining priorities

| Pri | Item | Addresses |
| --- | --- | --- |
| P0 | Make the benign verdict depend on coverage. Require, as successful queries: the trigger's process tree, network/DNS for the trigger's tree, and host context. Treat any failed, rejected or missing required query as a blocker, not just as an unknown. | F1 |
| P0 | Check benign contradictions against all descendants of the trigger (bounded walk over retrieved `parent_process_guid` links), and retrieve descendants actively when a benign verdict is drafted. | F2 |
| P0 | Make the token budget safe for dense content. Replace base64/hex blobs in prompts with `len + sha256` (the decoded text is already shown), and lower the default ratio to ≤ 2.0 or measure it at startup. Make `context_overflow_suspected` set the status to `incomplete` and block benign. Confirm live how Ollama counts `prompt_eval_count` when a prefix is cached. | F3 |
| P0 | Treat instruction-like host context as a benign blocker, like evidence. | F4 |
| P0 | Add the two missing tests. This is cheap and locks in existing behaviour. | F6 |
| P1 | Query around the anchor rather than from the window start (two half-window queries, or sort by distance from the anchor). Re-run BM-X07. | F5 |
| P1 | Run the opt-in live Ollama and Wazuh suites in a lab (still the largest unverified area). Add case-sensitivity and non-eventchannel records to the Wazuh checks. | F3, F8 |
| P2 | Honour or reject cancellation during the final report and record it; take the lock in `shutdown`. Drop or redefine the "fully correct" headline; add Playwright to a `[browser]` extra; stop tests writing tracked files. | F7, F9–F11 |
| Next | Third-party-authored cases, signer/hash enrichment, per-tool deadlines (unchanged from REVIEW.md). | — |

## 5. How to re-run

```bash
python -m pytest -q                                   # 228 with playwright installed
for p in benign gate hostctx window cancel; do python docs/validation/followup/probe_$p.py .; done
PY=python docs/validation/followup/mutate.sh . /tmp/mut
# tokenizer.json for Qwen2.5 (e.g. from npm @lenml/tokenizer-qwen2_5/models/) + pip install tokenizers
python docs/validation/followup/probe_tokens.py . path/to/tokenizer.json
```
