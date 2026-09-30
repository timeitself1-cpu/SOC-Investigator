# Security model

The model can request only six allowlisted, bounded, read-only telemetry tools.
It cannot run shell commands, remediate endpoints or execute recommendations
(`RecommendedAction.executed` is typed `Literal[False]`). The application itself
writes local reports and a run journal, and makes configured backend/model requests.

## Evidence and assessments

The application assigns evidence IDs and rejects fabricated references. Structured
claims and ATT&CK hypotheses must meet conservative prerequisites with host/process/
account/time correlation where appropriate. Rejected or untagged finding narratives
become retrieved observations. Reports separate application-generated **observed
facts** from **hypotheses** (prerequisites met, intent not verified) and from the
model's **narrative** (never semantically verified). Strong verdicts require
correlated evidence; incomplete collection cannot clear an alert as benign.

A benign verdict additionally requires that the **alerted process itself** was
launched by a management agent whose **full path** lies in its vendor install
directory. A management-agent *name* elsewhere (e.g. `C:\Users\Public\AgentExecutor.exe`)
is tagged `masquerade_suspect` and blocks a benign verdict. No signer/hash data is
available in this schema, so path checks reduce but do not eliminate spoofing;
benign conclusions still require analyst confirmation (a verification step says so).

Free prose, confidence (uncalibrated), recommendations and intent are not verified.
An adversarial model can still mislead an analyst; read-only tools do not make its
conclusions trustworthy.

## Untrusted telemetry and browser output

Display fields are bounded and screened for instruction-like content (heuristic).
Any flagged record blocks a benign verdict and produces a verification step.
JSON framing escapes delimiter characters; host context from the SIEM is sanitized
and labelled untrusted in prompts and reports. Evidence identity, tool bounds and
report checks do not depend on the model obeying the prompt.

Jinja templates escape displayed values; the activity feed and evidence filters use
text nodes and pre-escaped data attributes only. Markdown export escapes markup and
collapses line structure so prose cannot create headings, rules or code blocks.
The CSP restricts scripts to local files (no inline script, no `eval` — verified in
a real browser, where `eval`-based automation is refused).

## Failures and redaction

Backend and model failures are reduced to a stable kind (`timeout`, `tls`, `auth`,
`permission`, `index_missing`, `mapping`, `partial_results`, `invalid_response`,
`rate_limited`, `unavailable`, …) with a fixed message. Raw exception text, URLs and
response bodies are not placed in the trace, the UI, the run journal or model prompts.
Error bodies are inspected only for error-type tokens.

A wildcard index that matches nothing (e.g. archives not enabled) is an explicit
`index_missing` failure rather than an empty result, so "no data" is never presented
as "no activity".

## Local service boundaries

The default bind address is 127.0.0.1. There is **no authentication**. Host checks
permit loopback names and the configured host; unsafe requests with a foreign Origin
or cross-site Fetch Metadata are rejected (verified out-of-process: 403 / 400). These
are browser defenses, not access control for API clients. Do not expose this MVP
publicly without a separately designed authentication and authorization model.

Active investigations are deduplicated by alert and capped (default two). Cancellation
is cooperative. On shutdown active runs are cancelled and stragglers recorded as
interrupted. Run history (`reports/runs/`) and reports (`reports/*.json`) are
restored on restart. They contain telemetry and model transcripts: they are not
encrypted or signed, and need filesystem access control and retention handling.

## Backend and data handling

Wazuh HTTP operations use a read-only request allowlist and configured index scopes.
Index-qualified references prevent collisions; partial searches fail explicitly;
expired API tokens are refreshed once. Query windows, results, process trees,
evidence counts, model steps, wall-clock time and prompt size are bounded.
Use least-privilege Wazuh credentials and TLS verification. Credentials belong in the
environment or the ignored `.env`; `Settings.safe_dict()` redacts password fields.

## Verification limits

Controls are covered by unit, contract (mock-transport) and real-browser tests.
Live Wazuh mappings/auth/TLS and real Ollama behaviour have **not** been verified;
opt-in integration tests are provided in `tests/integration/`. See REVIEW.md and
VALIDATION.md.
