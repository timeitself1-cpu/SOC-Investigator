# Independent benchmark suite — design

Purpose: measure the investigator on cases it was **not** built around. The five
demo fixtures (`investigator/cases`) were authored together with the rules they
test; passing them shows internal consistency, not accuracy.

## How ground truth was set

1. Each scenario was written as a short story (who did what, on which host, why).
2. From the story alone, `truth.json` records: the label (`malicious`, `benign`,
   `ambiguous`), acceptable verdicts, forbidden verdicts, forbidden structured
   claims, required source records, and optional expectations (injection flag,
   status, truncation disclosure).
3. Truth was committed **before** the system was run on the suite
   (see git history: the "benchmark ground truth" commit precedes any results).
4. Expected outcomes are not edited to match system output. If a truth entry is
   later found to be wrong, the correction and its reason go in `CHANGES.md` in
   this directory — never silently.

Required evidence is listed as raw record ids (what an analyst must retrieve),
not as this system's indicator tags, so evidence recall does not depend on the
rules being evaluated.

## Dimensions covered

| Dimension | Cases |
| --- | --- |
| Legitimate administrative tools | B01, B02, B03, A01, X04, X06, B05 (v0.2.1) |
| Masquerading as a management agent | M01 |
| Prompt injection in telemetry | X03 (malicious), X04 (benign) |
| Prompt injection in host/asset context | X09 (v0.2.1) |
| Suspicious activity by a descendant of an admin-launched process | M06 (v0.2.1) |
| Cross-host coincidence | X01 |
| Cross-process coincidence on one host | X06 |
| Reordered / out-of-order records | M02, M03, X02 |
| Missing evidence (retention gap) | X05 |
| Noise and result truncation | X07, X08 (v0.2.1: post-alert record behind pre-alert noise) |
| Authentication edge cases | B04, M02, X01, X02 |

## Label semantics

* `malicious`: a competent analyst would escalate. Correct = `suspicious` or
  `likely_malicious`; `benign` or `insufficient_evidence` is a miss (FN).
* `benign`: a competent analyst would close. `likely_malicious` is always a
  false positive; `suspicious` is an escalation false positive (reported
  separately); `insufficient_evidence` is "not cleared" (safe but costly).
* `ambiguous`: the telemetry cannot decide. Strong verdicts outside the
  acceptable set are counted as over-confident.

## Limits

22 synthetic cases (18 from v0.2.0, 4 added in v0.2.1 with truth committed before any
v0.2.1 run) are a regression and failure-mode suite, not a statistically
meaningful detection benchmark. All payloads are synthetic and non-functional.
