# qwen2.5:7b-instruct — before (v0.3) and after (v0.3.1)

## Before: two live runs on v0.3 (provided by the user, preserved unmodified)

Files: [`../v0.3/live_ollama_runs/`](../v0.3/live_ollama_runs/). Model `qwen2.5:7b-instruct`,
fixture backend, 2026-09-30.

| | INC-002 (LSASS dump via comsvcs.dll) | INC-004 (8 failed logons, then success) |
| --- | --- | --- |
| Run | `run-20201d86…` | `run-f8f901d0…` |
| Verdict / status | `insufficient_evidence` / `incomplete` | `insufficient_evidence` / `incomplete` |
| Claims proposed | `benign_administration` on all 3 findings | `benign_administration` on the only finding |
| Claims accepted | none | none |
| Invalid-argument rejections | 1 (`get_network_activity scope="process"`) | 0 |
| Duplicate requests | 3 (same `get_process_tree`) | 3 (same `get_logon_activity`) |
| Loop stop | yes | yes |
| Host context / network collected | no / no | no / no |
| Revision | did not exist in v0.3 | did not exist in v0.3 |
| Model exchanges | 9 | 5 |

In both runs the gates held: no false benign, and the unsupported claim was rejected.
The failure was in the contract. The model was not told what each claim means, which
argument values were allowed, or that its request had already been answered. Its
rejected claims were never fed back to it.

## After: v0.3.1 with qwen2.5:7b-instruct — **NOT VERIFIED (not run)**

The v0.3.1 development container had no Ollama. `ollama.com` and
`registry.ollama.ai` were unreachable, and the model could not be downloaded. No
real-model result exists for v0.3.1. Run this on the machine that produced the
"before" runs:

```bash
ollama pull qwen2.5:7b-instruct
bash docs/validation/v0.3.1/run_ollama_eval.sh            # Linux/macOS
# Windows: powershell -ExecutionPolicy Bypass -File docs\validation\v0.3.1\run_ollama_eval.ps1
```

This runs `python -m investigator acceptance --repeats 3` at `num_ctx` 16384 and 8192,
and `python -m investigator benchmark --repeats 3` at 16384. It writes every report and
`acceptance.json` to `docs/validation/v0.3.1/ollama_after/`. Commit that folder as it
is, whether the criteria pass or fail.

### Acceptance criteria (amended, behavior-based)

Every criterion must hold in every repeat.

* **INC-004:** verdict `suspicious` or `likely_malicious`, with the authentication
  attack pattern (`brute_force`) accepted and no loop stop. A confirmed account
  compromise is **not** required.
* **INC-002:** verdict `suspicious` or `likely_malicious`, with LSASS credential-dumping
  **behavior** (`credential_theft`, defined as dumping behavior, not proven theft)
  accepted, no invalid-argument rejection and no loop stop. Proof of credential
  theft or successful compromise is **not** required. T1003.001 is optional.
* **INC-001 to INC-004:** `benign_administration` is neither accepted nor left in the
  final draft.
* **INC-005:** stays `benign` with every collection requirement met.
* `likely_malicious` is never required. Behavior, intent and outcome remain distinct:
  claims assert observed behavior only.

### What the harness does with the observed behaviour (scripted, not a real model)

`scripted_replay.py` replays the exact decisions and drafts of the two live runs
(`ObservedQwen`, which ignores all feedback). It also runs a model that makes the same
first mistakes but reads the v0.3.1 feedback (`FeedbackFollower`). Output:
[`scripted_replay.txt`](scripted_replay.txt).

| | ObservedQwen on v0.3.1 | FeedbackFollower on v0.3.1 |
| --- | --- | --- |
| INC-002 | insufficient_evidence / incomplete; still loops (4 duplicates); revision performed, same draft | **suspicious**, `credential_theft` accepted, 0 invalid args, no loop stop |
| INC-004 | insufficient_evidence / incomplete; loop stop; revision performed, same draft | **suspicious**, `brute_force` + `account_compromise` accepted |
| INC-005 | `suspicious` (its draft verdict), claim accepted | **benign**, all requirements met |
| Acceptance | 0 / 7 criteria | 7 / 7 criteria |

What this shows:

1. A model that ignores the contract is still contained. There is no false benign, and
   unsupported claims are rejected.
2. The feedback channels carry enough information for a compliant model to reach the
   supported behavior without any gate being loosened.

Whether qwen2.5:7b is compliant enough is exactly what the real run measures.
