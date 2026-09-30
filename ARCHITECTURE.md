# Architecture

## Design goal

`alert → autonomous evidence collection → grounded investigation → auditable report`

The value is the pipeline and its guarantees, not framework machinery. The system
is deliberately small: a bounded loop, a strict data model, an evidence store that
owns identity, an allowlist of read-only tools, and two swappable interfaces (LLM,
backend). No multi-agent orchestration, no vector DB, no remediation.

## The core invariant

> Model reasoning is kept separate from evidence truth. **Application code owns
> evidence identity.** The model proposes findings; the application validates them;
> the evaluator determines whether the investigation succeeded.

Concretely:

- Evidence IDs (`EV-0001`, …) are minted **only** by `EvidenceStore.add()` when a
  backend record is retrieved through a tool. The LLM never sees an ID it can
  fabricate that would validate.
- A `Finding` requires ≥1 evidence ID (Pydantic-enforced). During validation, any
  ID not present in the store is stripped; a finding with no surviving ID is dropped.
- A finding's **claims** (a controlled vocabulary) and **ATT&CK techniques** survive
  only if the cited evidence satisfies a deterministic support predicate
  (`attack.py`). "The model recognized suspicious text" is never sufficient.
- If no findings survive, a `suspicious`/`likely_malicious`/`benign` verdict is
  automatically downgraded to `insufficient_evidence`.

## Components

### Data model — `models.py`
Strict (`extra="forbid"`) Pydantic models: `Alert`, `Evidence`, `Finding`,
`AttackMapping`, `RecommendedAction`, `ToolCall`, `LLMExchange`,
`InvestigationTrace`, `InvestigationReport`, plus the model-facing output schemas
`AgentDecision` and `ReportDraft`. `Verdict` is a 4-value `Literal`; `confidence`
is a bounded float; `RecommendedAction.executed` is `Literal[False]` — the type
system itself forbids an "executed" action.

### Evidence store — `evidence.py`
The single source of evidence identity. On `add()` it:
1. dedupes by backend `event_ref` (re-retrieval returns the same ID);
2. sanitizes every field (strips control/bidi chars, bounds length);
3. derives **indicators** deterministically (e.g. `powershell`, `encoded_command`,
   `office_parent`, `lsass_target`, `external_destination`, `failed_logon`) —
   these are application facts, not model opinions;
4. screens text for prompt-injection and flags the item;
5. decodes PowerShell `-EncodedCommand` for display (still treated as untrusted).

### Tools — `tools.py`
Six bounded, read-only tools: `search_events`, `get_process_tree`,
`get_process_details`, `get_network_activity`, `get_related_events`,
`get_host_context`. `dispatch()` enforces the allowlist, validates arguments
against per-tool Pydantic schemas, clamps result counts and time windows, runs the
tool, and returns a `ToolCall` for the audit trail **whatever happens** (including
rejection or error — a tool never crashes the loop). Evidence produced by a tool is
registered in the store, which assigns the IDs.

### Backends — `backends/`
`TelemetryBackend` is a `Protocol` with five read methods. `FixtureBackend` loads
`cases/` into an in-memory store; `WazuhBackend` queries the Wazuh indexer
(`_search`) and optional server API. Both return `NormalizedEvent`s via the shared
`normalize.py`, so fixtures and live Wazuh look identical to the agent. This is what
makes "replace FixtureBackend with WazuhBackend without changing the agent" true.

### LLM — `llm/`
`InvestigatorModel` is a `Protocol` with one method, `complete()`. `OllamaModel`
is a thin `/api/chat` client (`format=json`, temperature 0, fixed seed).
`MockInvestigatorModel` is a deterministic rule-based analyst that reads the
structured `<STATE_JSON>` block and drives a realistic investigation — used by the
demo and the entire test suite.

### Agent loop — `agent.py`
```
seed the triggering event (system-initiated, not model-initiated)
repeat up to max_steps:
    build STATE_JSON (alert + evidence-so-far + tools + catalogs)   # telemetry = untrusted data
    ask model for one AgentDecision (JSON, validated; bounded repair on malformed output)
    if finish or unparseable: break
    dispatch the tool  → ToolCall recorded, evidence registered
    stop if evidence budget reached
ask model for a ReportDraft (JSON, validated; bounded repair)
validate_report(draft) → InvestigationReport   # the invariant is enforced here
```
Every prompt, response, tool request/result, timing, model name, token count, and
error is captured in `InvestigationTrace`.

### Report + exports — `report.py`
`validate_report()` implements the invariant and builds the timeline (marking which
evidence was cited) and ATT&CK mappings. Exports to JSON and Markdown.

### Evaluation — `evaluation/evaluator.py`
Scores each fixture against `expectations.json` using the **indicators actually
attached to retrieved evidence** (not prose): required-evidence recall, forbidden
claims, evidence-reference validity, verdict acceptability, completion, tool count,
runtime.

### Web + CLI — `app.py`, `service.py`, `main.py`
FastAPI renders the incident queue, a live investigation view (polls a JSON activity
feed; shows human-readable activity, never raw chain-of-thought), and the completed
report with expandable evidence and JSON/Markdown export. `InvestigationService`
runs each investigation on a background thread. The CLI mirrors all of this.

## Request flow (web)

```
GET  /                     → queue.html (alerts + latest run status)
POST /investigate/{alert}  → start background run → 303 → /run/{run_id}
GET  /run/{run_id}         → investigation.html (JS polls /api/run/{run_id})
GET  /api/run/{run_id}     → {status, activity[], next_index}
GET  /report/{run_id}      → report.html
GET  /export/{run_id}.json → JSON
GET  /export/{run_id}.md   → Markdown
```

## Why these boundaries

- **Protocol-based backend/LLM** → new SIEMs or models without touching the engine.
- **Application-owned evidence identity** → the model cannot manufacture support.
- **Deterministic indicators + support predicates** → claims are checkable by code.
- **Everything read-only, allowlisted, bounded** → the blast radius is "reads some
  logs", enforced by types and dispatch, not by asking the model nicely.

---

## v0.2 additions

### Collection coverage (what was and was not seen)
Every tool call records a human-readable `scope` (host, window, filters), an
`outcome` (`complete`, `empty`, `truncated`, `partial`, `failed`, `rejected`,
`duplicate`), a classified `error_kind`, and `gaps` (known unknowns).
`report.build_coverage()` turns these into `InvestigationReport.coverage`:
counts, hosts/categories queried, backend caveats (e.g. "only rule-matched events
are searchable"), and explicit unknowns (earlier ancestry, never-queried network
activity, evidence hidden from the model by the context budget).

Report status is derived from that ledger:

| Condition | Status |
| --- | --- |
| cancelled by analyst / shutdown | `cancelled` |
| model produced no valid report | `failed` |
| backend failure, result-cap truncation, step/time/evidence budget, missing trigger, model stopped gathering, evidence omitted from the final prompt | `incomplete` |
| ancestry beyond the retained window (`partial`), rejected or duplicate model requests | stays `completed`; disclosed as known unknowns |

The last row is a deliberate change: real Sysmon always records a parent GUID and
long-lived parents predate any window, so treating that as a failure made every
realistic report `incomplete` and a benign verdict unreachable.

### Report structure
`validate_report()` now builds, alongside the validated findings:
`observed_facts` (code-generated statements from cited/trigger records),
`hypotheses` (each accepted claim and ATT&CK mapping with the prerequisite it met),
`verification_steps` (deterministic next checks from hypotheses and coverage gaps),
an application-generated `summary`, and `model_narrative` (the model's prose, kept
only when validation made no corrections, always labelled unverified).

### Benign guard
`benign_blockers()` withholds a benign verdict unless the *alerted process itself*
was launched by a management agent from its install directory, no correlated
malicious prerequisites exist, no contradicting indicators appear on the process tree
(Office parent, external destination, user-writable path, masquerade) or host
(LSASS access, dump file, Run key, scheduled task), no telemetry is instruction-like,
and collection was complete.

### Context budget
`InvestigationAgent._build_state()` renders the prompt state under
`(num_ctx - num_predict - 256) * chars_per_token - repair_reserve` characters,
compacting in recorded levels (shorter attributes → shorter tool history →
one-line low-priority evidence → omit lowest-priority evidence). Priority: trigger,
evidence with indicators, then nearest in time. `LLMExchange` records budget,
compaction level, evidence shown/omitted, prompt/response SHA-256 and sizes,
`done_reason`, and suspected server-side context overflow.

### Run lifecycle
`InvestigationService` journals each run to `<reports_dir>/runs/<run_id>.json`
(atomic writes; the final record is durable *before* the status is published),
replays the journal on startup (in-flight runs become `interrupted`), supports
cooperative cancellation (`POST /run/{id}/cancel`), and on shutdown cancels active
runs, waits `shutdown_grace_seconds`, and records stragglers as interrupted.

### Errors
`errors.py` classifies every backend/model failure into a stable kind with a fixed
safe message. Response bodies are inspected only for error-type tokens (e.g.
`index_not_found_exception` → `index_missing`) and never copied.

### Evaluation
`evaluation/evaluator.py` scores the five demo fixtures. `evaluation/benchmark.py`
runs the independent suite with per-case isolated backends and reports detection,
claims, evidence and operational metrics separately.
