# Investigator

**A local-first AI security investigation agent for Windows that turns security
signals into evidence-grounded incident investigations.**

Install and run it on a Windows PC → open the local dashboard → see security
signals raised from the computer's own event logs → click **Investigate** → the
agent collects local Windows telemetry with bounded, read-only tools → you get an
evidence-cited report with a complete audit trail. No VM, SIEM, SSH, cloud service or
external LLM is involved: the model runs locally in **Ollama** (or a deterministic
mock model for demos and tests), and telemetry comes from **Sysmon, Windows Security,
PowerShell and Microsoft Defender** event logs on the same machine.

```
DETECTION       deterministic rules       "This deserves investigation."     (signals.py)
    ↓
INVESTIGATION   bounded agent loop        "What happened?"                   (agent.py + read-only tools)
    ↓
EVIDENCE        application-owned IDs     "What proves it?"                  (evidence.py)
    ↓
ASSESSMENT      validated, gated verdict  "What does the evidence support?"  (report.py)
    ↓
RECOMMENDATION  never executed            "What should a human consider?"
```

Evidence identity is owned by the application. Findings must cite retrieved records,
and structured claims must meet conservative evidence prerequisites. A `benign`
verdict must be **earned** by complete, application-verified collection (process tree,
network activity, asset context, a host-level signal check, and a model view of all
priority evidence). Missing or unreadable telemetry is reported as a coverage gap —
never treated as "nothing found". These checks do **not** semantically verify
model-written prose; verdicts remain assessments requiring analyst review.

Status: v0.3.0. The Windows event log backend is **implemented and unit-tested against
recorded event XML, but has not yet been run on a real Windows machine** — see
[V0.3_RELEASE_NOTES.md](V0.3_RELEASE_NOTES.md) and the real-world validation procedure in
[`docs/validation/v0.3/`](docs/validation/v0.3/). History: [CHANGELOG.md](CHANGELOG.md),
[VALIDATION.md](VALIDATION.md), [REVIEW_FOLLOWUP.md](REVIEW_FOLLOWUP.md), [REVIEW.md](REVIEW.md).

---

## Architecture

```
Windows PC
  Browser ── http://127.0.0.1:8000
     │
     ▼
  FastAPI app ─► InvestigationService ─► InvestigationAgent (bounded loop)
                                            ├─ InvestigatorModel   Ollama (local) | mock
                                            ├─ Tools (allowlist)   9 read-only, schema-validated tools
                                            ├─ EvidenceStore       owns EV-xxxx IDs
                                            └─ TelemetryBackend ─► WindowsEventBackend (default product path)
                                                                     ├─ Sysmon  ├─ Windows Security
                                                                     ├─ PowerShell ├─ Microsoft Defender
                                                                   FixtureBackend (demo incidents, tests)
                                                                   WazuhBackend   (optional integration)
```

The engine depends only on the `TelemetryBackend` and `InvestigatorModel` protocols;
the model never touches Windows APIs, event-log queries or XPath. See
[ARCHITECTURE.md](ARCHITECTURE.md).

## Screenshots

| Dashboard (Windows replay) | Investigation activity | Missing Sysmon shown honestly |
| --- | --- | --- |
| `docs/screenshots/v03_dashboard_replay.png` | `v03_investigation_rw01.png` | `v03_dashboard_no_sysmon.png` |

The v0.3 screenshots use the packaged **synthetic** Windows event samples (replay).

---

## Modes

| `SOCI_BACKEND` | Telemetry | Use |
| --- | --- | --- |
| `windows` | This computer's event logs (read-only, Windows only) | **The product.** |
| `windows-replay` | Recorded Windows event XML (`--replay-dir`; defaults to packaged synthetic samples) | Demos anywhere; replaying exports from a real machine |
| `fixture` | 5 built-in demo incidents | Deterministic demo, tests, benchmark |
| `wazuh` | A Wazuh indexer (optional integration) | Existing Wazuh labs |

`SOCI_LLM=ollama` (local model) or `mock` (deterministic, no LLM). CLI flags `--llm`,
`--backend`, `--replay-dir` override the environment / `.env`.

---

## Windows 11 setup (PowerShell)

```powershell
# 1. Python 3.12+ and the project
cd $HOME\Documents            # unzip soc_investigator_mvp.zip here
cd soc-investigator
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1   # if blocked: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
python -m pip install --upgrade pip
pip install -e .                  # installs pywin32 on Windows automatically

# 2. Local model
#    Install Ollama from https://ollama.com/download, then:
ollama pull qwen2.5:7b-instruct

# 3. Check which telemetry this account can read
python -m investigator --backend windows sources

# 4. Start the investigator and open http://127.0.0.1:8000
$env:SOCI_BACKEND = "windows"; $env:SOCI_LLM = "ollama"
python -m investigator serve
```

After this, investigation happens in the browser; you should not need Event Viewer.

### Telemetry sources (recommended, one-time, administrator)

| Source | Why | Enable |
| --- | --- | --- |
| **Sysmon** (recommended) | Process GUIDs, ancestry, network, DNS, file, registry — required for process-tree and network coverage | Install Sysinternals Sysmon with a configuration that logs process creation (1), network connections (3) and DNS (22), e.g. `sysmon64 -accepteula -i <config.xml>` |
| Windows Security | Logons (4624/4625), special privileges (4672), scheduled tasks (4698), process creation fallback (4688) | `auditpol /set /subcategory:"Process Creation" /success:enable` and enable command-line capture (`ProcessCreationIncludeCmdLine_Enabled`); logon auditing is on by default |
| PowerShell | Script blocks (4104) | Enable PowerShell script block logging (Group Policy or `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`) |
| Microsoft Defender | Detections (1116/1117) | On by default when Defender is the active antivirus |

Missing sources do not crash the investigator: the dashboard shows them (✓ active,
⚠ limited, ○ not installed, ✗ access denied) and investigations that need them are
marked incomplete. Without Sysmon, process ancestry cannot be established, so a
`benign` verdict is never granted.

### Privileges

The web app runs **unprivileged**. Reading the Security log (and, by default, the
Sysmon log) requires membership in **Administrators** or the local **Event Log
Readers** group. Recommended (least privilege): add your account once, then sign
out and in again:

```powershell
# elevated PowerShell, one time
net localgroup "Event Log Readers" $env:USERNAME /add
```

Access is detected per source at startup and per query; a denial is shown as
`access denied` and becomes an investigation-completeness condition — it is never
read as "no events". Details: [SECURITY.md](SECURITY.md#windows-event-log-privileges).

### Demo without Windows or Ollama

```powershell
python -m investigator --llm mock --backend windows-replay serve   # synthetic Windows events
python -m investigator --llm mock --backend fixture serve          # the 5 demo incidents
```

Command-line equivalents: `list`, `investigate <ID>`, `evaluate`, `benchmark`,
`sources`, `diagnose`, `health`.

---
## Ollama details

```powershell
# Install Ollama for Windows from https://ollama.com/download , then:
ollama pull qwen2.5:7b-instruct     # a solid 7B instruct model for a 4070 Super
ollama serve                         # usually already running as a service

# Point the agent at Ollama and run:
$env:SOCI_LLM = "ollama"
$env:SOCI_BACKEND = "fixture"
$env:SOCI_OLLAMA_MODEL = "qwen2.5:7b-instruct"
python -m investigator health         # verifies Ollama + model are reachable
python -m investigator serve
```

Any local instruct model that honors `format=json` works (e.g.
`llama3.1:8b-instruct`, `mistral:7b-instruct`). Set `SOCI_OLLAMA_MODEL` to match
what you pulled. Temperature defaults to `0.0` for determinism.

> The **mock** model is always available as a fallback and is what the tests use,
> so you can evaluate the full product even before pulling a model.

---

## Optional: Wazuh integration

Wazuh typically runs on a separate Ubuntu VM. This agent talks to it **read-only**
over the network — **no SSH, no shell on the SIEM**.

1. In your Wazuh indexer, create a **read-only** user.
2. Put credentials in `.env` (git-ignored) — never in code:

   ```powershell
   $env:SOCI_BACKEND = "wazuh"
   $env:SOCI_WAZUH_INDEXER_URL = "https://YOUR-WAZUH:9200"
   $env:SOCI_WAZUH_INDEXER_USER = "readonly-analyst"
   $env:SOCI_WAZUH_INDEXER_PASSWORD = "..."          # or set in .env
   $env:SOCI_WAZUH_VERIFY_TLS = "true"               # provide a CA bundle in prod
   python -m investigator --backend wazuh diagnose --host YOUR-WINDOWS-AGENT
   ```

   `diagnose` runs only read-only requests and reports each check separately:
   indexer auth, alerts index, archives index presence (a missing index is an
   explicit `index_missing` failure, never "no activity"), Sysmon telemetry and
   field names for the host, and server-API auth.

3. **Surrounding events.** By default Wazuh only *indexes* events that matched a
   rule (`wazuh-alerts-*`). To let the agent pull non-alert Sysmon context
   (process trees, network events), enable **archives** (`logall_json`) and an
   archives index, then set `SOCI_WAZUH_EVENTS_INDEX` to it. Without archives,
   the agent still works but sees only rule-matched events.

4. Ensure **Sysmon** is deployed on your Windows endpoints and its channel is
   forwarded to Wazuh (a standard Sysmon config such as SwiftOnSecurity's).

**Status of the Wazuh backend:** implemented against Wazuh's documented indexer
(`_search`) and server API, and unit-tested with a mocked HTTP transport. It has
**not** been run against a live Wazuh cluster by the author — see
[`VALIDATION.md`](VALIDATION.md). The query construction, read-only request
allowlist, normalization, and severity mapping are covered by tests; what remains
to confirm in your environment is index names, field mappings for your Sysmon
config, and TLS/auth. The **fixture mode is fully functional** and is the
supported demo path.

---

## Running tests

```powershell
python -m pytest -q                        # unit, contract, service, web, browser* tests
node --test tests/test_activity_dom.cjs    # activity-feed DOM tests (optional, needs Node)
```

Default tests use the mock model and fixture backend — **no Ollama or Wazuh
required**. `tests/test_failure_modes.py` simulates auth/permission/TLS/timeout/
missing-index/mapping failures through the real HTTP code with mock transports.
*`tests/test_browser_ui.py` runs in real Chromium when Playwright is installed
(`pip install playwright; python -m playwright install chromium`), otherwise skips.

### Live integration tests (opt-in)

```powershell
# Real Ollama (model must be pulled)
$env:SOCI_IT_OLLAMA = "1"
python -m pytest -m integration -v tests/integration/test_live_ollama.py

# Real Wazuh (read-only; uses your SOCI_WAZUH_* settings)
$env:SOCI_IT_WAZUH = "1"
$env:SOCI_IT_WAZUH_HOST = "YOUR-WINDOWS-AGENT"        # optional
$env:SOCI_IT_WAZUH_SELF_SIGNED = "1"                  # optional: expect a TLS failure without CA
$env:SOCI_IT_WAZUH_LIMITED_USER = "no-read-user"      # optional: expect "permission"
$env:SOCI_IT_WAZUH_LIMITED_PASSWORD = "..."
python -m pytest -m integration -v tests/integration/test_live_wazuh.py
```

These check the harness contract against the real services (model tag, structured
output, context accounting, timeouts; auth, TLS, permissions, missing archives,
field mapping, a read-only investigation of the newest alert). They have **not**
been run by the author — see VALIDATION.md.

## Evaluation

```powershell
python -m investigator --llm mock evaluate
# or JSON:
python -m investigator --llm mock evaluate --json
```

The evaluator runs each of the 5 demo fixtures through the agent and scores, per case:
required-evidence recall, unsupported claims, evidence-reference validity, verdict
acceptability, completion, tool-call count, and runtime — against machine-readable
`expectations.json` in each case folder. The demo fixtures were written together with
the rules they exercise, so passing them shows consistency, not accuracy.

### Independent benchmark

```powershell
python -m investigator --llm mock benchmark                 # deterministic pipeline
python -m investigator --llm ollama benchmark --out bench.json   # your local model
```

22 cases (malicious / benign / ambiguous; 4 added in v0.2.1) designed around failure modes the demo
fixtures never exercised: masquerading management agents, prompt injection,
cross-host and cross-process coincidences, reordered records, missing trigger
records, legitimate admin tools and noise-driven truncation. Ground truth was
committed before the system was run on it; see
`investigator/benchmarks/independent/DESIGN.md`. Metrics are reported separately:
false positives/negatives at two thresholds, benign-cleared rate, forbidden verdicts,
retained vs. proposed-then-rejected claims, evidence recall (retrieved and cited),
and operational failures. The output compares the agent with a trivial
always-`suspicious` classifier (which scores 21/22 "acceptable verdicts", so that
number alone shows nothing) and reports benign TP/FP, escalation TP/FN,
insufficient-evidence outcomes, coverage requirements met, context-overflow and
incomplete reports. `--adversary benign-after-investigation|benign-immediately`
swaps in an evaluation-only model that always proposes benign, to measure the
verdict gates (exit code 2 if it closes any non-benign case). The mock-model results
measure the pipeline and guards, not language-model judgement.

---

## The five fixture incidents

| ID | Scenario | Why it's here |
| --- | --- | --- |
| INC-001 | WINWORD → encoded PowerShell → outbound connection | Malicious-document style chain |
| INC-002 | `comsvcs.dll` MiniDump of LSASS | Credential dumping |
| INC-003 | Scheduled task + Run-key persistence | Persistence |
| INC-004 | Many failed logons → one success (external IP) | Brute force → account compromise |
| INC-005 | **Benign** SCCM inventory: encoded PowerShell as SYSTEM to an internal host | Guards against "PowerShell = malicious" |

INC-005 deliberately *looks* like INC-001 (encoded PowerShell) but is legitimate.
A correct agent must not classify it `likely_malicious`, because the parent is a
management agent and the destination is internal. This is enforced by the
evaluator's `forbidden_claims`.

---

## Security model (summary)

Read-only is enforced **architecturally**, not by prompting. See
[`SECURITY.md`](SECURITY.md) for the full model. Highlights:

- There is **no** write/execute/shell/remediation tool in the codebase.
- Tool dispatch uses an explicit **allowlist**; unknown tool names are rejected.
- Every tool argument is validated by a strict Pydantic schema; result counts and
  time windows are clamped; investigation iterations are bounded.
- **Evidence IDs are assigned by the application**, never by the LLM. Findings that
  cite non-existent evidence are dropped.
- Telemetry is treated as **untrusted data**: it is sanitized, screened for
  prompt-injection, clearly delimited in prompts, and never followed as instructions.
- Prompts are kept inside the model context budget by recorded compaction (never
  silent server-side truncation). Long base64/hex/high-entropy runs are replaced in
  prompts by bounded descriptions (type, length, SHA-256 prefix, head/tail); the
  evidence store keeps the full value. Token use is estimated at ≤ 2 characters per
  token; a suspected overflow marks the investigation incomplete. Each model
  exchange records prompt/response SHA-256, sizes, estimated tokens, omitted and
  summarized evidence counts and any audit clipping.
- Backend and model failures are classified (`timeout`, `tls`, `auth`, `permission`,
  `index_missing`, `mapping`, …) and never propagate raw response text.
- A benign verdict must be **earned** (v0.2.1). Application code checks four
  collection requirements from the resolved tool-call records — the alerted
  process tree (ancestry and all descendants), host-wide network/DNS activity
  covering ±15 min of the alert, trustworthy asset context, and an assessment
  prompt that showed every retrieved record in full — plus administrative context
  on the alerted process itself (management agent **by install path**, not name),
  no contradicting indicators anywhere in the process tree or host, and no
  instruction-like telemetry, alert fields or asset metadata. Any failure yields
  `insufficient_evidence`, never a guess.
- Run history is journaled to disk; runs interrupted by a restart are recorded as such.
  Telemetry and model output can contain sensitive data; protect `reports/` and exports.

---

## Limitations

- **The live Windows event log reader has not been run on Windows yet.** Parsing,
  normalization, discovery, signals and investigations are verified against recorded
  (synthetic) event XML only. Run the procedure in `docs/validation/v0.3/` on a real
  Windows 11 machine before relying on it.
- Only the local computer is investigated; there is no multi-endpoint support.
- A `benign` verdict needs a recognized endpoint-management agent (Intune Management
  Extension, Configuration Manager) as the alerted process's parent. On an unmanaged
  home PC, legitimate activity ends as `insufficient_evidence`, not `benign`.
- Capability discovery infers "limited" logging from the absence of recent events; it
  does not query service state (a Sysmon service stopped minutes ago still looks active).
- The **mock model** is a deterministic rule-based analyst — a stand-in for a real
  LLM, useful for demos/tests.
- Fixtures and benchmark cases are synthetic; they are not a detection benchmark.
- The **Ollama client and Wazuh backend are not live-verified** (see VALIDATION.md).
- The prompt budget assumes at most 2 characters per token (measured 2.45-3.2 for
  compacted prompts with the Qwen2.5 tokenizer). Use `SOCI_OLLAMA_NUM_CTX` ≥ 8192;
  smaller contexts cannot hold a useful prompt at that ratio. JSON-schema `format`
  needs Ollama ≥ 0.5 (set `SOCI_OLLAMA_STRUCTURED_OUTPUT=false` to fall back to
  `format=json`).
- Cancellation is cooperative: a model or backend request already in flight finishes
  (bounded by its own timeout); the run then ends as `cancelled`, including when the
  request was the final assessment.
- Confidence is model-reported and uncalibrated.
- Findings are only as good as the telemetry retrieved; absence of evidence is not
  evidence of absence, and the agent says so in each report's limitations.
- No authentication on the local web UI (by design — it binds to `127.0.0.1`).

## Roadmap

- **Run RW-01…RW-05 on a real Windows 11 machine** with Sysmon and a local model;
  record raw outputs (the v0.3 go/no-go question).
- Decide how legitimate *unmanaged* administration can earn `benign` (e.g. signer and
  hash verification of the parent) without weakening the gates.
- Service-state checks (Sysmon running) in capability discovery.
- Measure the benchmark with real local models; grow the suite with third-party cases.

## Project layout

```
soc-investigator/
  investigator/
    app.py            FastAPI dashboard
    agent.py          bounded investigation loop
    models.py         strict Pydantic data model
    evidence.py       evidence store (owns IDs) + sanitization + injection screen
    tools.py          allowlisted read-only tools
    attack.py         MITRE ATT&CK catalog + evidence-support rules
    report.py         report validation + JSON/Markdown export
    config.py         env / .env settings (secrets redacted)
    service.py        run manager: bounded concurrency, journaled history, cancel, shutdown
    errors.py         classified, redacted failure kinds
    main.py           CLI (serve/list/investigate/evaluate/benchmark/sources/diagnose/health)
    signals.py        deterministic local signal rules (detection -> investigation starting points)
    compaction.py     prompt-only blob compaction + conservative token estimate
    llm/              base / ollama / mock models (+ evaluation-only benign proposer)
    backends/         base protocol / windows (+ windows_events, winevt_reader) / fixture / wazuh / normalize
    windows_samples/  SYNTHETIC Windows event XML for windows-replay (packaged)
    evaluation/       evaluator (demo cases) + benchmark (independent suite)
    cases/INC001..INC005/            demo fixtures (packaged)
    benchmarks/independent/BM-*/     independent benchmark + DESIGN.md (packaged)
    templates/, static/
  tests/                  unit/contract/service/web/browser tests; tests/integration = opt-in live
  build_fixtures.py       regenerates the demo fixtures
  build_benchmark.py      regenerates the independent benchmark
  build_windows_samples.py regenerates the synthetic Windows event samples
  docs/validation/        exact outputs of the verification runs
  REVIEW.md  ARCHITECTURE.md  SECURITY.md  VALIDATION.md
```

## First command to run on Windows

```powershell
py -3.12 -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -e .; python -m investigator --backend windows sources
```

Then start the dashboard (`$env:SOCI_BACKEND="windows"; python -m investigator serve`) and open
<http://127.0.0.1:8000>.
