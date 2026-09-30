# SOC Investigation Agent

A **standalone, local-first AI SOC investigation agent**. You give it one security
alert; it autonomously gathers surrounding telemetry with bounded, read-only
tools, correlates the evidence, classifies the incident, recommends response
actions (without executing them), and shows the whole investigation — with a
complete audit trail — in a local web dashboard.

Evidence identity is owned by the application. Findings must cite retrieved records,
and structured claims must meet conservative evidence prerequisites. These checks do
**not** semantically verify all model-written prose, recommendations, verdicts or confidence.
Those remain assessments requiring analyst review.

See [AUDIT_AND_IMPROVEMENTS.md](AUDIT_AND_IMPROVEMENTS.md) for the September 2026
review, fixes, verification, corrected benchmark expectations and remaining limitations.
Use `start-demo.ps1` after installation for the mock/fixture dashboard.

Everything runs on your machine: a local LLM via **Ollama**, or a deterministic
**mock model** for demos and tests. No cloud, no external APIs, no SSH into a
SIEM VM required.

---

## What it does

```
        Alert
          │
          ▼
   Investigation Engine ──► Local LLM (Ollama)  or  deterministic Mock model
          │                      (proposes next step / draft findings)
          │
          ├──► bounded read-only tools  (search_events, get_process_tree, …)
          │            │
          │            ▼
          │      Telemetry Backend  ──►  FixtureBackend   (5 built-in incidents)
          │                          └►  WazuhBackend      (live lab, read-only)
          ▼
   Evidence store (application-owned IDs)  ──►  Report validation  ──►  Web UI + JSON/MD export
```

1. Inspect the alert → 2. decide what evidence is needed → 3. call read-only tools →
4. reconstruct process/activity context → 5. correlate events → 6. produce
evidence-backed findings → 7. classify (`benign` / `suspicious` /
`likely_malicious` / `insufficient_evidence`) → 8. recommend actions (never
executed) → 9. display in a local UI → 10. keep a full audit trace.

## Architecture diagram

```
Browser
   │  http://127.0.0.1:8000
   ▼
FastAPI app (investigator/app.py)
   │
   ▼
InvestigationService ──► InvestigationAgent (bounded loop)
                              │
                              ├─ InvestigatorModel   (llm/ollama.py | llm/mock.py)
                              ├─ Tools (allowlist)   (tools.py  → read-only only)
                              ├─ EvidenceStore       (evidence.py → owns EV-xxxx IDs)
                              └─ TelemetryBackend     (backends/fixture.py | backends/wazuh.py)
                                       │
                                       └─ shared normalizer (backends/normalize.py)
```

The engine depends only on the `TelemetryBackend` **protocol** and the
`InvestigatorModel` **protocol**. Swapping Fixture → Wazuh, or Mock → Ollama,
changes nothing in the agent.

## Screenshots

See [`docs/screenshots/`](docs/screenshots):

| Incident queue | Investigation (live) | Report (malicious) | Report (benign) |
| --- | --- | --- | --- |
| `queue.png` | `investigation_progress.png` | `report_inc001.png` | `report_inc005_benign.png` |

---

## Three modes

| Mode | LLM | Backend | Use |
| --- | --- | --- | --- |
| 1 | `mock` | `fixture` | Deterministic demo + the whole test suite. No Ollama needed. |
| 2 | `ollama` | `fixture` | Real local agent against the 5 built-in incidents. |
| 3 | `ollama` | `wazuh` | Real investigation against your Wazuh lab. |

Select with `SOCI_LLM` / `SOCI_BACKEND` (env or `.env`), or `--llm` / `--backend` on the CLI.

---

## Windows 11 installation (PowerShell)

```powershell
# 1. Get the project
cd $HOME\Documents
# (unzip soc_investigator_mvp.zip here, then:)
cd soc-investigator

# 2. Create and activate a virtual environment (Python 3.12+)
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
# If activation is blocked:  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4. (Optional) create your local config
Copy-Item .env.example .env
```

### Deterministic demo (no Ollama, no Wazuh)

```powershell
$env:SOCI_LLM = "mock"
$env:SOCI_BACKEND = "fixture"
python -m investigator serve
```

Open <http://127.0.0.1:8000>, pick **INC-001**, click **Investigate**, watch the
activity, and read the evidence-grounded report. This is the recommended first run.

Command-line equivalents:

```powershell
python -m investigator --llm mock list
python -m investigator --llm mock investigate INC-001
python -m investigator --llm mock evaluate
```

---

## Ollama setup (Mode 2)

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

## Wazuh configuration (Mode 3)

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
   python -m investigator --backend wazuh health
   ```

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
python -m pytest -q
```

Tests use the mock model and fixture backend only — **no Ollama or Wazuh
required**. Integration tests (if any are added) are marked `integration` and
deselected by default.

## Evaluation

```powershell
python -m investigator --llm mock evaluate
# or JSON:
python -m investigator --llm mock evaluate --json
```

The evaluator runs each of the 5 fixtures through the agent and scores, per case:
required-evidence recall, unsupported claims, evidence-reference validity, verdict
acceptability, completion, tool-call count, and runtime — against machine-readable
`expectations.json` in each case folder. It grades the **investigation**, not the
prose.

---

## The five fixture incidents

| ID | Scenario | Why it's here |
| --- | --- | --- |
| INC-001 | WINWORD → encoded PowerShell → outbound C2 | Classic malicious-document chain |
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
- An audit trace (bounded prompts/responses, tool calls, timings, tokens, errors)
  is retained. Telemetry and model output can contain sensitive data; protect exports.

---

## Limitations

- The **mock model** is a deterministic rule-based analyst — a stand-in for a real
  LLM, useful for demos/tests. Real analytic nuance comes from Mode 2/3.
- Fixtures are representative but small; they are not a threat-detection benchmark.
- The **Wazuh backend is not live-verified** (see above and `VALIDATION.md`).
- Findings are only as good as the telemetry retrieved; absence of evidence is not
  evidence of absence, and the agent says so in each report's limitations.
- No authentication on the local web UI (by design — it binds to `127.0.0.1`).

## Roadmap

- Live-verify the Wazuh backend against a reference lab; add an archives-index recipe.
- Additional backends (Elastic/OpenSearch-generic, Splunk) behind the same protocol.
- Richer process-tree reconstruction (full descendant graph, not just direct children).
- Per-tenant asset/criticality enrichment and suppression lists.
- Optional signed, append-only audit log export.

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
    service.py        background run manager for the web UI
    main.py           CLI (serve/list/investigate/evaluate/health)
    llm/              base / ollama / mock models
    backends/         base protocol / fixture / wazuh / normalize
    evaluation/       evaluator
    templates/, static/
  cases/INC001..INC005/   events.json, alert.json, expectations.json, hosts.json
  tests/                  pytest suite (mock + fixture only)
  build_fixtures.py       regenerates the fixture telemetry
  ARCHITECTURE.md  SECURITY.md  VALIDATION.md
```

## First command to run on Windows

```powershell
py -3.12 -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt; $env:SOCI_LLM="mock"; $env:SOCI_BACKEND="fixture"; python -m investigator serve
```

Then open <http://127.0.0.1:8000> and investigate **INC-001**.
