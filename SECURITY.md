# Security model

The model can request only six allowlisted, bounded, read-only telemetry tools.
It cannot run shell commands, remediate endpoints or execute recommendations.
The application itself writes local reports and makes configured backend/model requests.

## Evidence and assessments

The application assigns evidence IDs and rejects fabricated references. Structured
claims and ATT&CK hypotheses must meet conservative prerequisites, with host/process/
account/time correlation where appropriate. Rejected or untagged finding narratives
become retrieved observations. Strong verdicts require correlated evidence; incomplete
collection cannot clear an alert as benign. Free prose, confidence, recommendations and
intent are not semantically verified. An adversarial model can still mislead an analyst;
read-only tools do not make its conclusions trustworthy.

## Untrusted telemetry and browser output

Display fields are bounded and screened for instruction-like content. Screening is
heuristic, not proof against prompt injection. JSON framing escapes delimiter characters.
Evidence identity, tool bounds and report checks do not depend on obeying the prompt.
Jinja templates escape displayed values, activity uses text nodes, and Markdown export
escapes untrusted markup. A CSP restricts scripts to local assets. Raw JSON and audit
text remain untrusted content and may be clipped.

## Local service boundaries

The default bind address is 127.0.0.1. There is no authentication. Host checks permit
loopback names and the configured host; unsafe requests with foreign Origin or cross-site
Fetch Metadata are rejected. These are browser defenses, not access control for API clients.
Do not expose this MVP publicly. Wildcard binds do not allow arbitrary LAN Host names.
Responses use no-store and nosniff headers.

Active investigations are deduplicated by alert and capped (default two). In-memory
history is capped (default 100); completed JSON files are retained separately. Persistence
uses generated run IDs and atomic replacement. Disk failures remain visible and the
in-memory report can be exported. History is not restored automatically after restart,
and unfinished daemon jobs are not drained on shutdown.

## Backend and data handling

Wazuh HTTP operations use a read-only request allowlist and configured index scopes.
Index-qualified references prevent collisions, partial searches fail explicitly, and
query windows, results, process trees, evidence counts and model steps are bounded.
Use least-privilege Wazuh credentials and TLS verification. Credentials belong in the
local environment or ignored .env file; Settings.safe_dict() redacts password fields.
Do not embed credentials in URLs. Raw telemetry, model output and backend error text
can still contain sensitive information. Reports are not encrypted, are not signed,
and require appropriate local filesystem access controls and retention handling.

## Verification limits

Regression tests cover the stated controls with fixtures and mock transports. Live
Wazuh mappings/auth/TLS and real Ollama behavior have not been verified in this review.
See AUDIT_AND_IMPROVEMENTS.md for exact findings, changes and remaining limitations.
