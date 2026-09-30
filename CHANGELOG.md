# Changelog

## 0.2.1 — Investigation integrity fix (2026-09-30)

Narrowly scoped to the findings in [REVIEW_FOLLOWUP.md](REVIEW_FOLLOWUP.md) (F1–F11).
No new product features, no architecture changes, no remediation. All R1–R18 fixes
from 0.2.0 are preserved. Evidence: `docs/validation/v0.2.1/`.

### Verdict integrity
- **Benign must be earned (F1).** New `CollectionRequirement` ledger
  (`report.coverage.requirements`), computed by application code from each tool
  call's resolved target (`ToolCall.target`), never from model prose:
  `process_tree` (the alerted process's ancestry + descendants; a parent outside the
  retained window is acceptable, a missing target or truncation is not),
  `network_activity` (host-wide, not truncated, covering ±15 min of the alert),
  `host_context` (found for the alerted host, no instruction-like text),
  `model_visibility` (the assessment prompt showed every retrieved record in full and
  no prompt overflow was suspected). Any unmet requirement withholds benign →
  `insufficient_evidence`. The model may still propose benign.
- **Descendant-aware guard (F2).** `get_process_tree` walks all descendant
  generations breadth-first (bounded: 8 generations, the per-tool result limit;
  reaching a bound is truncation). The benign guard evaluates every record performed
  by the alerted process or any descendant, via a cycle-safe fixed-point closure over
  retrieved parent links (same host only). Cyclic relationships mark the tree
  untrustworthy.
- **Host-context injection (F4).** Asset metadata is screened like telemetry; the flag
  is recorded on the tool call, shown to the model as `injection_suspected`, fails
  the `host_context` requirement, and blocks benign. Instruction-like alert fields
  (title, user, host) also block benign.

### Context-size safety (F3)
- New `investigator/compaction.py`. Base64 (with UTF-16LE/PowerShell detection), hex
  (≥130 chars, so MD5–SHA-512 hashes stay verbatim), high-entropy tokens and mostly
  non-ASCII text are replaced **in prompts only** by a bounded marker: type, length,
  decoded byte count, SHA-256 prefix, 12-char head/tail. URLs with a domain are kept
  verbatim. Evidence attributes, raw records and hashes are untouched.
- `prompt_chars_per_token` default 3.0 → **2.0**, capped at 2.0 (an older `.env` with
  3.0 is clamped, not rejected). The budget reserves `num_predict`, 256 template tokens
  and 1,400 tokens for a repair turn.
- Each exchange records `estimated_prompt_tokens`, `prompt_token_limit`,
  `blobs_compacted`, `evidence_summarized`. A pre-flight estimate over the limit, or a
  server-reported prompt ≥ 97% of `num_ctx` or above the prompt limit, sets
  `context_overflow_suspected`, adds a `context:` trace error, marks the report
  `incomplete`, and blocks benign.
- Attribute truncation at compaction levels ≥ 1 never cuts a compaction marker.

### Retrieval (F5)
- Time-centered retrieval for `search_events`, `get_related_events`,
  `get_network_activity` and `get_process_details`: the nearest events before and
  at/after the anchor are fetched separately (`EventQuery.order`, honoured by the
  fixture and Wazuh backends) and balanced; unused quota on one side goes to the other.
  Truncation gaps state what was kept.

### Other
- **Cancellation (F7):** a cancel accepted during the final-report call now ends the
  run `cancelled` (draft discarded, still audited); repairs stop once cancelled.
- **Shutdown race (F11):** the running→interrupted transition happens under the run lock.
- **Evaluation (F9):** benchmark output compares the agent with an always-`suspicious`
  baseline and adds integrity metrics (benign TP/FP, escalation TP/FN,
  insufficient-evidence count, required-evidence recall, unsupported claims,
  evidence-reference validity, coverage requirements met, context-overflow and
  incomplete counts). The legacy "fully correct" headline is kept and labelled.
  `--adversary benign-after-investigation|benign-immediately` runs evaluation-only
  benign proposers. 4 new cases (BM-X08, M06, X09, B05), truth committed first.
- **Hygiene (F10):** browser tests only rewrite tracked screenshots with
  `SOCI_UPDATE_SCREENSHOTS=1`.
- Tests: 228 → 279 (+4 real-tokenizer tests, skipped unless `SOCI_TOKENIZER_JSON`).

### Behaviour changes to note
- Fewer benign closures when collection is thin: an investigation that never queried
  the tree, host-wide network activity or asset context can no longer end `benign`.
  Mock benchmark: benign TP unchanged (2/7: BM-B01, BM-B05); X09 no longer benign.
- `SOCI_OLLAMA_NUM_CTX` below 8192 cannot hold the minimal prompt at 2 chars/token.
- Each retrieval tool issues two backend queries (before/after the anchor) per category.

## 0.2.0 — see [REVIEW.md](REVIEW.md)
## 0.1.x — see [AUDIT_AND_IMPROVEMENTS.md](AUDIT_AND_IMPROVEMENTS.md)
