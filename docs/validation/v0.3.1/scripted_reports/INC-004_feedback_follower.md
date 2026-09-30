# Investigation INV\-d84a7a76e9

> **Recommendations only — no response actions were executed\.**

- **Alert:** INC\-004 — Multiple authentication failures followed by success
- **Host:** DC\-01
- **Verdict:** `suspicious`  |  **Model confidence (uncalibrated):** 0.60
- **Model:** scripted\-feedback\-follower  |  **Backend:** fixture  |  **Status:** completed
- **Started:** 2026-09-30T13:54:39.581199+00:00  |  **Completed:** 2026-09-30T13:54:39.609602+00:00

## Summary (application-generated)

Assessment: suspicious \(model confidence 0\.60, uncalibrated\)\. Status: completed\. 9 observed fact\(s\) are cited; 4 hypothesis\(es\) met structured prerequisites \(intent is not verified\)\. Coverage: 5 queries, 0 failed, 0 truncated, 0 partial; 0 known unknown\(s\)\.

## Observed facts (from retrieved records)

- `2026-09-29T03:11:02+00:00` EV-0002 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\) (ref INC004\-0001)
- `2026-09-29T03:11:09+00:00` EV-0003 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\) (ref INC004\-0002)
- `2026-09-29T03:11:15+00:00` EV-0004 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\) (ref INC004\-0003)
- `2026-09-29T03:11:22+00:00` EV-0005 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\) (ref INC004\-0004)
- `2026-09-29T03:11:31+00:00` EV-0006 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\) (ref INC004\-0005)
- `2026-09-29T03:11:40+00:00` EV-0007 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\) (ref INC004\-0006)
- `2026-09-29T03:11:48+00:00` EV-0008 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\) (ref INC004\-0007)
- `2026-09-29T03:11:55+00:00` EV-0009 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\) (ref INC004\-0008)
- `2026-09-29T03:12:05+00:00` EV-0001 — Triggering event\. Logon succeeded for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\) (ref INC004\-0009)

## Hypotheses (prerequisites checked; intent not verified)

- H-001 [claim] brute\_force — Prerequisite met: 3 distinct failures for the same host/account/source within 15 minutes; evidence EV-0001, EV-0002, EV-0003, EV-0004, EV-0005, EV-0006, EV-0007, EV-0008, EV-0009
- H-002 [claim] account\_compromise — Prerequisite met: a success following 3 failures for the same host/account/source within 15 minutes; evidence EV-0001, EV-0002, EV-0003, EV-0004, EV-0005, EV-0006, EV-0007, EV-0008, EV-0009
- H-003 [attack_technique] T1078 Valid Accounts — Prerequisite met: a success following 3 distinct failures for the same host, account and source within 15 minutes; evidence EV-0001, EV-0002, EV-0003, EV-0004, EV-0005, EV-0006, EV-0007, EV-0008, EV-0009
- H-004 [attack_technique] T1110 Brute Force — Prerequisite met: 3 distinct failed logons for the same host, account and source within 15 minutes; evidence EV-0001, EV-0002, EV-0003, EV-0004, EV-0005, EV-0006, EV-0007, EV-0008, EV-0009

## Verification steps

- Review the full authentication log for the account and source; check lockouts and other targeted accounts\. _(Hypothesis 'brute\_force' is based on structured prerequisites, not confirmed intent\.)_
- Confirm with the account owner; review activity performed by the session after the successful logon\. _(Hypothesis 'account\_compromise' is based on structured prerequisites, not confirmed intent\.)_

## Model narrative (unverified)

Behavior supported by the listed evidence\.

## Collection coverage

- Queries: 5 · failed 0 · truncated 0 · partial 0 · rejected 0 · duplicates 1 · complete: yes
- Hosts: DC\-01 · Categories: asset context, authentication, dns, network, privilege, trigger
  - tc-001 get\_event [complete] triggering event reference INC004\-0009 (1)
  - tc-002 get\_host\_context [complete] asset context for DC\-01 (1)
  - tc-003 get\_logon\_activity [complete] logon activity on DC\-01 2026\-09\-29 02:12–04:12 UTC (9)
  - tc-004 get\_logon\_activity [duplicate] logon activity on DC\-01 2026\-09\-29 02:12–04:12 UTC (0)
  - tc-005 get\_logon\_activity [complete] logon activity on DC\-01 2026\-09\-29 02:12–04:12 UTC (9)
  - tc-006 get\_network\_activity [empty] network\+DNS on DC\-01 2026\-09\-29 02:12–04:12 UTC (0)
- Required for benign closure:
  - NOT met: process tree — the triggering event has no process identity; process ancestry cannot be established
  - met: network activity — host\-wide network/DNS activity around the alert was retrieved completely
  - met: host context — asset context for the alerted host was retrieved
  - met: host signals — no other security signals on the host around the alert
  - met: model visibility — the assessment prompt showed every retrieved record in full

## Host context (untrusted asset metadata)

- host: DC\-01; os: Windows Server 2022; ip: 10\.20\.5\.5; role: Domain Controller; criticality: critical; agent\_status: active

## Findings

### F-001: Repeated failed logons \(authentication attack pattern\)  _(severity: high)_

At least 3 failed logons for the same host, account and source within 15 minutes\.

- Evidence: EV-0001, EV-0002, EV-0003, EV-0004, EV-0005, EV-0006, EV-0007, EV-0008, EV-0009
- Claims: brute_force

### F-002: Successful logon after repeated failures \(POSSIBLE compromise pattern\)  _(severity: high)_

A successful logon followed at least 3 failures for the same host, account and source within 15 minutes\.

- Evidence: EV-0001, EV-0002, EV-0003, EV-0004, EV-0005, EV-0006, EV-0007, EV-0008, EV-0009
- Claims: account_compromise

## MITRE ATT&CK (hypotheses)

| Technique | Name | Tactic | Findings | Evidence |
| --- | --- | --- | --- | --- |
| T1078 | Valid Accounts | initial\-access | F-001, F-002 | EV-0001, EV-0002, EV-0003, EV-0004, EV-0005, EV-0006, EV-0007, EV-0008, EV-0009 |
| T1110 | Brute Force | credential\-access | F-001, F-002 | EV-0001, EV-0002, EV-0003, EV-0004, EV-0005, EV-0006, EV-0007, EV-0008, EV-0009 |

## Timeline

- `2026-09-29T03:11:02+00:00` [★] EV-0002 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- `2026-09-29T03:11:09+00:00` [★] EV-0003 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- `2026-09-29T03:11:15+00:00` [★] EV-0004 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- `2026-09-29T03:11:22+00:00` [★] EV-0005 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- `2026-09-29T03:11:31+00:00` [★] EV-0006 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- `2026-09-29T03:11:40+00:00` [★] EV-0007 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- `2026-09-29T03:11:48+00:00` [★] EV-0008 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- `2026-09-29T03:11:55+00:00` [★] EV-0009 — Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- `2026-09-29T03:12:05+00:00` [★] EV-0001 — Logon succeeded for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)

## Evidence

- **EV-0001** (authentication, windows\-security, ref INC004\-0009; sha256 ae5e9f9257f86add…): Logon succeeded for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- **EV-0002** (authentication, windows\-security, ref INC004\-0001; sha256 518d10eaf96b510e…): Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- **EV-0003** (authentication, windows\-security, ref INC004\-0002; sha256 92f96d5f7be268fd…): Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- **EV-0004** (authentication, windows\-security, ref INC004\-0003; sha256 31fe2affdb0c2ebc…): Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- **EV-0005** (authentication, windows\-security, ref INC004\-0004; sha256 88a9885fcfc65de9…): Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- **EV-0006** (authentication, windows\-security, ref INC004\-0005; sha256 eec86e23c3722261…): Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- **EV-0007** (authentication, windows\-security, ref INC004\-0006; sha256 780cf4e35c4d7933…): Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- **EV-0008** (authentication, windows\-security, ref INC004\-0007; sha256 54c8b7d0c71a28b9…): Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)
- **EV-0009** (authentication, windows\-security, ref INC004\-0008; sha256 0a139469f45c4d50…): Logon failed for CORP\\administrator from 45\.155\.205\.233 \(logon type 3\)

## Limitations

- Automated validation checks evidence references and structured claim prerequisites only\. Retained model narrative, verdict, confidence and recommendations are assessments requiring analyst review\. ATT&amp;CK mappings are behavioral hypotheses, not proof of malicious intent or successful compromise\.

## Model draft vs. accepted

- Draft verdict: `suspicious` → accepted verdict: `suspicious`
- Claims proposed: brute\_force, account\_compromise · accepted: account\_compromise, brute\_force
- ATT&CK proposed: T1110, T1078 · accepted: T1078, T1110
- Claims describe observed behavior only; intent and outcome are not verified.

## Validation-feedback revision

- Performed: yes · changed the assessment: yes
- First draft: verdict `suspicious` → validated `insufficient_evidence`; accepted claims none; rejected benign\_administration
- Revised draft: verdict `suspicious`; accepted claims brute\_force, account\_compromise
- The report below is the validated revision; the first draft is in the audit trace\.

## Audit disclosure

- Model exchanges: 7; repair attempts: 0; exchanges with clipped audit copies or omitted evidence: 0.