"""Deterministic mock analyst model.

It stands in for a real local LLM so the whole product and the test suite run
with no Ollama. It is a genuine (if simple) rule-based analyst: every decision
and every finding is derived ONLY from the evidence the agent has actually
retrieved, communicated through the structured <STATE_JSON> block the agent
includes in the prompt. It never invents evidence IDs and never emits a claim
whose supporting indicator is absent — so it behaves correctly on the benign
case (INC-005) too, not by knowing the incident but by reading the evidence.
"""

from __future__ import annotations

import json
import re

from .base import LLMResponse

_STATE_RE = re.compile(r"<STATE_JSON>\s*(\{.*?\})\s*</STATE_JSON>", re.DOTALL)


class MockInvestigatorModel:
    name = "mock-analyst"

    def complete(self, messages: list[dict[str, str]], *, temperature: float | None = None) -> LLMResponse:
        # A repair turn appends messages after the prompt; use the most recent
        # message that carries the state block.
        text = next((m["content"] for m in reversed(messages) if "<STATE_JSON>" in m.get("content", "")),
                    messages[-1]["content"] if messages else "")
        state = self._parse_state(text)
        if state.get("phase") == "final_report":
            out = self._build_report(state)
        else:
            out = self._decide(state)
        return LLMResponse(text=json.dumps(out), model=self.name, prompt_tokens=len(text) // 4,
                           completion_tokens=len(json.dumps(out)) // 4)

    # -- parsing ---------------------------------------------------------
    @staticmethod
    def _parse_state(text: str) -> dict:
        m = _STATE_RE.search(text)
        if not m:
            return {}
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            return {}

    # -- decision phase --------------------------------------------------
    def _decide(self, state: dict) -> dict:
        alert = state.get("alert", {})
        host = alert.get("host")
        evidence = state.get("evidence", [])
        called = state.get("tools_called", [])
        steps_left = state.get("steps_left", 0)

        def has_call(tool: str, ok_only: bool = True) -> bool:
            return any(c.get("tool") == tool and (c.get("status") == "ok" or not ok_only) for c in called)

        def attempted(tool: str) -> bool:
            return any(c.get("tool") == tool for c in called)

        # 1. Host context first.
        if not attempted("get_host_context"):
            return self._tool("get_host_context", {"host": host}, "Establish asset context for the host")

        # 2. Pull the triggering event and its immediate surroundings.
        if not attempted("search_events"):
            return self._tool("search_events", {"host": host, "window_minutes": 15},
                              "Retrieve the triggering event and nearby telemetry")

        # 3. Reconstruct process ancestry for the primary process, if any.
        proc_ev = self._first(evidence, lambda e: e.get("category") in ("process", "process_access") and e.get("process_guid"))
        if proc_ev and not attempted("get_process_tree"):
            return self._tool("get_process_tree", {"evidence_id": proc_ev["evidence_id"]},
                              "Reconstruct process ancestry to establish how the process started")

        # 4. Pull full detail for that process (file/registry/access it performed).
        if proc_ev and not attempted("get_process_details"):
            return self._tool("get_process_details", {"evidence_id": proc_ev["evidence_id"]},
                              "Collect the full activity of the primary process")

        # 5. Network activity, if we haven't seen it yet.
        if not attempted("get_network_activity"):
            return self._tool("get_network_activity", {"host": host},
                              "Check outbound network activity on the host")

        # 6. Correlate around the trigger.
        trigger_ev = self._first(evidence, lambda e: e.get("is_trigger")) or (evidence[0] if evidence else None)
        if trigger_ev and not attempted("get_related_events"):
            return self._tool("get_related_events", {"evidence_id": trigger_ev["evidence_id"], "window_minutes": 15},
                              "Correlate events surrounding the trigger")

        # Otherwise: enough gathered, or nearly out of budget → finish.
        del steps_left, has_call
        return {"action": "finish", "arguments": {}, "purpose": "Sufficient evidence collected; compiling report"}

    @staticmethod
    def _tool(tool: str, args: dict, purpose: str) -> dict:
        return {"action": "call_tool", "tool": tool, "arguments": args, "purpose": purpose}

    @staticmethod
    def _first(items, pred):
        for it in items:
            if pred(it):
                return it
        return None

    # -- report phase ----------------------------------------------------
    def _build_report(self, state: dict) -> dict:
        evidence = state.get("evidence", [])
        ind: dict[str, list[str]] = {}
        for e in evidence:
            for tag in e.get("indicators", []):
                ind.setdefault(tag, []).append(e["evidence_id"])

        def ids(*tags: str) -> list[str]:
            out: list[str] = []
            for t in tags:
                out.extend(ind.get(t, []))
            return list(dict.fromkeys(out))

        cat_ids: dict[str, list[str]] = {}
        for e in evidence:
            cat_ids.setdefault(e.get("category", "other"), []).append(e["evidence_id"])

        findings: list[dict] = []
        techniques: set[str] = set()
        malicious_signals = 0
        benign_signals = 0

        # Office-spawned obfuscated interpreter.
        if ind.get("office_parent") and ind.get("powershell"):
            ev = ids("office_parent", "powershell", "encoded_command")
            claims = ["office_child_process", "execution"]
            tq = ["T1059.001"]
            if ind.get("encoded_command"):
                claims.append("obfuscation"); tq.append("T1027")
            findings.append(self._f("Office application spawned an obfuscated PowerShell process",
                                    "A PowerShell process was created as a child of an Office application, "
                                    "warranting review of the document and process context. Ancestry alone does not "
                                    "prove that a user opened a malicious file.", "high", ev, claims, tq))
            techniques.update(tq); malicious_signals += 2
        elif ind.get("powershell") and ind.get("encoded_command"):
            ev = ids("powershell", "encoded_command")
            claims = ["execution", "obfuscation"]
            # Preserve the observation in the benign administration demo without
            # presenting an approved automation pattern as an adversarial mapping.
            administrative = ind.get("management_agent_parent") and not any(
                ind.get(tag) for tag in ("external_destination", "lsass_target", "scheduled_task", "run_key"))
            tq = [] if administrative else ["T1059.001", "T1027"]
            findings.append(self._f("Encoded PowerShell execution observed",
                                    "PowerShell was launched with an encoded command. This can be malicious or "
                                    "legitimate automation; parent process and destination determine which.",
                                    "medium", ev, claims, tq))
            techniques.update(tq); malicious_signals += 1

        # Management-agent parent → legitimate administration signal.
        if ind.get("management_agent_parent"):
            ev = ids("management_agent_parent")
            findings.append(self._f("Process launched by a software-management agent",
                                    "The process was spawned by a recognized endpoint-management agent, indicating "
                                    "a possible administrative workflow. Confirm the job and parent identity with the owner.",
                                    "informational", ev, ["benign_administration"], []))
            benign_signals += 2

        # Credential access.
        if ind.get("lsass_target") and ind.get("memory_dump_file"):
            ev = ids("lsass_target", "memory_dump_file")
            findings.append(self._f("Credential-dumping behavior against LSASS",
                                    "LSASS access and a memory dump were observed. Correlate the process identity and "
                                    "dump contents to assess possible credential exposure.", "critical", ev, ["credential_theft"], ["T1003.001"]))
            techniques.add("T1003.001"); malicious_signals += 3

        # Persistence.
        if ind.get("scheduled_task") or ind.get("run_key"):
            ev = ids("scheduled_task", "run_key")
            tq = []
            if ind.get("scheduled_task"):
                tq.append("T1053.005")
            if ind.get("run_key"):
                tq.append("T1547.001")
            findings.append(self._f("Persistence mechanism established",
                                    "A scheduled task and/or a registry Run key was created to launch a payload, "
                                    "establishing persistence.", "high", ev, ["persistence"], tq))
            techniques.update(tq); malicious_signals += 2

        # Brute force / account compromise.
        if len(ind.get("failed_logon", [])) >= 3:
            ev = ids("failed_logon")
            findings.append(self._f("Repeated authentication failures (brute force)",
                                    f"{len(ev)} failed logon attempts were observed against the account, indicating "
                                    "password guessing.", "high", ev, ["brute_force"], ["T1110"]))
            techniques.add("T1110"); malicious_signals += 1
            if ind.get("successful_logon"):
                sev = ids("failed_logon", "successful_logon")
                findings.append(self._f("Successful logon following repeated failures",
                                        "A successful logon occurred after multiple failures from the same source, "
                                        "indicating a likely account compromise.", "high", sev,
                                        ["account_compromise"], ["T1078"]))
                techniques.add("T1078"); malicious_signals += 2

        # Network.
        if ind.get("external_destination"):
            ev = ids("external_destination")
            findings.append(self._f("Outbound connection to an external address",
                                    "Telemetry records an outbound connection to an external address. "
                                    "This alone does not establish command-and-control, transfer, or exfiltration.",
                                    "medium", ev, ["network_connection"], []))
            malicious_signals += 1
        elif ind.get("internal_destination"):
            ev = ids("internal_destination")
            findings.append(self._f("Outbound connection to an internal host",
                                    "The observed network connection was to an internal address, consistent with "
                                    "normal internal communication.", "low", ev, ["network_connection"], []))
            benign_signals += 1

        # Fallback finding so a report is never empty when evidence exists.
        if not findings and evidence:
            first = evidence[0]["evidence_id"]
            findings.append(self._f("Triggering event retrieved",
                                    "The alert's triggering event was retrieved, but surrounding telemetry did not "
                                    "provide enough corroboration to characterize the activity.",
                                    "low", [first], [], []))

        verdict, confidence, summary = self._verdict(malicious_signals, benign_signals, ind, len(evidence))

        limitations = ["This investigation used only retrieved telemetry; absence of evidence is not proof of absence.",
                       "No response actions were taken; recommendations require human review."]
        if any(e.get("injection_suspected") for e in evidence):
            limitations.append("Some telemetry contained text resembling instructions; it was treated as untrusted data.")

        actions = self._actions(verdict, ind)

        return {
            "verdict": verdict, "confidence": confidence, "summary": summary,
            "findings": findings, "recommended_actions": actions, "limitations": limitations,
        }

    @staticmethod
    def _f(title, desc, severity, evidence_ids, claims, techniques):
        return {"title": title, "description": desc, "severity": severity,
                "evidence_ids": evidence_ids, "claims": claims, "attack_techniques": techniques}

    @staticmethod
    def _verdict(mal: int, ben: int, ind: dict, n_evidence: int):
        if n_evidence == 0:
            return "insufficient_evidence", 0.2, "No evidence could be retrieved for this alert."
        strong = bool(ind.get("lsass_target") or (ind.get("scheduled_task") and ind.get("run_key"))
                      or (ind.get("office_parent") and ind.get("external_destination"))
                      or (len(ind.get("failed_logon", [])) >= 3 and ind.get("successful_logon")))
        benign_dominant = ind.get("management_agent_parent") and not (
            ind.get("office_parent") or ind.get("external_destination") or ind.get("lsass_target")
            or ind.get("scheduled_task") or ind.get("run_key") or len(ind.get("failed_logon", [])) >= 3)
        if benign_dominant:
            return ("benign", 0.7,
                    "The encoded PowerShell activity was launched by an endpoint-management agent to an internal "
                    "host, consistent with legitimate automated administration rather than an attack.")
        if strong:
            return ("likely_malicious", min(0.9, 0.6 + 0.1 * mal),
                    "Multiple corroborating indicators point to malicious activity on the host.")
        if mal >= 1:
            return ("suspicious", min(0.75, 0.45 + 0.1 * mal),
                    "The retrieved evidence shows suspicious behavior that warrants analyst review, but is not fully "
                    "conclusive on its own.")
        return ("insufficient_evidence", 0.35,
                "The retrieved evidence did not clearly indicate malicious or benign activity.")

    @staticmethod
    def _actions(verdict: str, ind: dict) -> list[dict]:
        if verdict == "benign":
            return [{"action": "Close the alert as benign after confirming the management-agent job schedule",
                     "rationale": "Activity matches expected endpoint-management automation.", "priority": "low"},
                    {"action": "Consider narrowly scoped tuning after validating the approved job and command",
                     "rationale": "Avoid suppressing unrelated PowerShell activity.", "priority": "low"}]
        if verdict == "insufficient_evidence":
            return [{"action": "Collect missing telemetry and review the alert with the asset owner",
                     "rationale": "The available evidence does not support a response decision.", "priority": "medium"}]
        actions = [{"action": "Review the findings and consider host containment under the incident-response procedure",
                    "rationale": "Confirm scope and business impact before taking response actions.", "priority": "high"},
                   {"action": "Preserve a forensic image and the relevant telemetry",
                    "rationale": "Support deeper investigation and possible IR.", "priority": "medium"}]
        if ind.get("lsass_target"):
            actions.append({"action": "Reset credentials for accounts that authenticated on the host",
                            "rationale": "LSASS access may have exposed cached credentials.", "priority": "high"})
        if ind.get("successful_logon") and len(ind.get("failed_logon", [])) >= 3:
            actions.append({"action": "Disable or reset the targeted account and block the source address",
                            "rationale": "A successful logon followed brute-force attempts.", "priority": "high"})
        if ind.get("scheduled_task") or ind.get("run_key"):
            actions.append({"action": "Remove the persistence entries after evidence capture",
                            "rationale": "Prevent the payload from re-launching.", "priority": "medium"})
        if ind.get("external_destination"):
            actions.append({"action": "Investigate the external destination and process context before deciding on a block",
                            "rationale": "External network activity alone does not establish a malicious destination.", "priority": "medium"})
        return actions


class BenignProposerModel(MockInvestigatorModel):
    """Evaluation-only adversary: investigates like the mock analyst (or not at
    all), then always drafts a confident benign verdict tagged
    ``benign_administration`` that cites every retrieved record.

    It stands in for a wrong, over-eager or prompt-injected model. The
    application's verdict gates, not this model, must decide whether benign is
    admissible. Never used by ``serve`` or ``investigate``.
    """

    def __init__(self, investigate: bool = True) -> None:
        self.investigate = investigate
        self.name = "adversary-benign-after-investigation" if investigate else "adversary-benign-immediately"

    def _decide(self, state: dict) -> dict:
        if not self.investigate:
            return {"action": "finish", "arguments": {}, "purpose": "Looks like routine administration"}
        return super()._decide(state)

    def _build_report(self, state: dict) -> dict:
        ids = [e["evidence_id"] for e in state.get("evidence", [])][:50]
        if not ids:
            return {"verdict": "benign", "confidence": 0.95, "summary": "Routine administrative activity.",
                    "findings": [], "recommended_actions": [], "limitations": []}
        return {"verdict": "benign", "confidence": 0.95,
                "summary": "Routine administrative activity by a management agent; close the alert.",
                "findings": [{"title": "Administrative job", "description": "Launched by endpoint management.",
                              "severity": "informational", "evidence_ids": ids,
                              "claims": ["benign_administration", "execution"], "attack_techniques": []}],
                "recommended_actions": [{"action": "Close as benign", "rationale": "Administration",
                                         "priority": "low"}],
                "limitations": []}


ADVERSARIES = {
    "benign-after-investigation": lambda: BenignProposerModel(investigate=True),
    "benign-immediately": lambda: BenignProposerModel(investigate=False),
}
