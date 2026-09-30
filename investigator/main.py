"""Command-line entry point.

    python -m investigator serve           # launch the web dashboard
    python -m investigator list            # list alerts in the current backend
    python -m investigator investigate INC-001   # run one investigation, print report
    python -m investigator evaluate        # run all fixtures through the evaluator
    python -m investigator health          # check Ollama / backend wiring
    python -m investigator diagnose        # read-only live checks (auth, TLS, indexes, mapping, model)
    python -m investigator benchmark       # independent benchmark with separated metrics
    python -m investigator sources         # telemetry sources on this computer (windows backends)
    python -m investigator --llm ollama acceptance --repeats 3 --out DIR   # v0.3.1 real-model acceptance

Flags: --llm mock|ollama  --backend fixture|windows|windows-replay|wazuh  --replay-dir DIR  --max-steps N
"""

from __future__ import annotations

import argparse
import json
import sys

from .config import Settings, load_settings
from .report import report_to_json, report_to_markdown


def _settings_from_args(args: argparse.Namespace) -> Settings:
    overrides = {}
    if args.llm:
        overrides["llm"] = args.llm
    if args.backend:
        overrides["backend"] = args.backend
    if args.max_steps is not None:
        overrides["max_steps"] = args.max_steps
    if getattr(args, "replay_dir", None):
        overrides["windows_replay_dir"] = args.replay_dir
    return load_settings(**overrides)


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = _settings_from_args(args)
    print(f"Investigator — llm={settings.llm} backend={settings.backend} "
          f"model={settings.ollama_model if settings.llm=='ollama' else 'mock-analyst'}")
    print(f"Open http://{settings.host}:{settings.port}  (Ctrl+C to stop)")
    from .app import create_app

    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level="info")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    from .agent import build_agent

    settings = _settings_from_args(args)
    _, backend = build_agent(settings)
    for a in backend.list_alerts():
        print(f"{a.alert_id:<10} {a.severity:<9} {a.host:<16} {a.title}")
    return 0


def cmd_investigate(args: argparse.Namespace) -> int:
    from .agent import build_agent

    settings = _settings_from_args(args)
    agent, backend = build_agent(settings)
    alert = backend.get_alert(args.alert_id)
    if alert is None:
        print(f"unknown alert {args.alert_id!r}", file=sys.stderr)
        return 2

    def hook(ev):
        if not args.quiet:
            print(f"  [{ev.kind:>7}] {ev.message}", file=sys.stderr)

    report = agent.investigate(alert, activity_hook=hook)
    if args.markdown:
        print(report_to_markdown(report))
    elif args.json:
        print(report_to_json(report))
    else:
        print(f"\nVerdict: {report.verdict} (confidence {report.confidence:.2f})")
        print(f"Findings: {len(report.findings)} | Evidence: {len(report.evidence)} | "
              f"Tool calls: {len(report.trace.tool_calls)} | Valid: {report.validation.valid}")
        for f in report.findings:
            print(f"  - {f.finding_id} {f.title}  {f.evidence_ids}  claims={f.claims}")
        if report.attack_techniques:
            print("  ATT&CK:", ", ".join(m.technique_id for m in report.attack_techniques))
    if args.out:
        text = report_to_markdown(report) if args.out.endswith(".md") else report_to_json(report)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"written {args.out}", file=sys.stderr)
    return 0 if report.status == "completed" else 1


def cmd_evaluate(args: argparse.Namespace) -> int:
    from .evaluation.evaluator import run_evaluation

    settings = _settings_from_args(args)
    if settings.backend != "fixture":
        print("evaluate requires --backend fixture", file=sys.stderr)
        return 2
    res = run_evaluation(settings)
    if args.json:
        out = {"summary": res["summary"], "cases": res["cases"]}
        print(json.dumps(out, indent=2))
        return 0 if res["summary"]["failed"] == 0 and res["summary"]["cases"] > 0 else 1
    s = res["summary"]
    print(f"\nEvaluation: {s['passed']}/{s['cases']} passed  "
          f"(pass_rate={s['pass_rate']}, mean_recall={s['mean_evidence_recall']}, "
          f"invalid_refs={s['total_invalid_evidence_refs']}, forbidden_claims={s['total_forbidden_claims']})\n")
    for c in res["cases"]:
        status = "PASS" if c["passed"] else "FAIL"
        print(f"  {status}  {c['alert_id']:<9} verdict={c['verdict']:<20} "
              f"recall={c['evidence_recall']} tools={c['tool_calls']} findings={c['findings']}")
        for note in c["notes"]:
            print(f"        ! {note}")
    return 0 if s["failed"] == 0 and s["cases"] > 0 else 1


def cmd_health(args: argparse.Namespace) -> int:
    settings = _settings_from_args(args)
    healthy = True
    print(f"llm={settings.llm} backend={settings.backend}")
    if settings.llm == "ollama":
        from .llm.ollama import OllamaModel

        ok, msg = OllamaModel(settings).health()
        healthy = ok
        print(f"ollama: {'OK' if ok else 'FAIL'} — {msg}")
    else:
        print("ollama: skipped (llm=mock)")
    try:
        from .agent import build_agent

        _, backend = build_agent(settings)
        print(f"backend: OK — {len(backend.list_alerts())} alert(s) available")
    except Exception as exc:  # noqa: BLE001
        from .errors import safe_error
        kind, msg = safe_error(exc)
        print(f"backend: FAIL [{kind}] — {msg}")
        return 1
    return 0 if healthy else 1


def ollama_structured_probe(settings: Settings) -> dict:
    """One real structured-output round trip against the configured Ollama model."""
    import time as _time

    from .agent import _parse
    from .llm.ollama import OllamaModel
    from .models import AgentDecision

    model = OllamaModel(settings)
    messages = [{"role": "system", "content": "Respond with a single JSON object only."},
                {"role": "user", "content": 'Return exactly: {"action": "finish", "arguments": {}, '
                                            '"purpose": "diagnostic"}'}]
    t0 = _time.perf_counter()
    try:
        resp = model.complete(messages, schema=AgentDecision.model_json_schema())
    except Exception as exc:  # noqa: BLE001
        from .errors import safe_error
        kind, msg = safe_error(exc)
        return {"check": "structured output round trip", "ok": False, "kind": kind, "detail": msg}
    parsed, err = _parse(resp.text, AgentDecision)
    return {"check": "structured output round trip", "ok": parsed is not None,
            "kind": None if parsed else "model_output",
            "detail": (f"{(_time.perf_counter() - t0):.1f}s, prompt_tokens={resp.prompt_tokens}, "
                       f"eval_tokens={resp.completion_tokens}, done_reason={(resp.meta or {}).get('done_reason')}"
                       + ("" if parsed else f"; {err}"))}


def cmd_diagnose(args: argparse.Namespace) -> int:
    """Read-only checks of the configured model and backend, for lab bring-up."""
    settings = _settings_from_args(args)
    rows: list[dict] = []
    if settings.llm == "ollama":
        from .llm.ollama import OllamaModel

        ok, msg = OllamaModel(settings).health()
        rows.append({"check": f"ollama model {settings.ollama_model}", "ok": ok, "kind": None, "detail": msg})
        if ok:
            rows.append(ollama_structured_probe(settings))
    if settings.backend == "wazuh":
        from .backends.wazuh import WazuhBackend, WazuhConfigError

        try:
            backend = WazuhBackend(settings)
        except WazuhConfigError as exc:
            rows.append({"check": "wazuh configuration", "ok": False, "kind": "auth", "detail": str(exc)})
        else:
            rows.extend(backend.probe(host=args.host))
            rows.extend({"check": "caveat", "ok": True, "kind": None, "detail": c}
                        for c in backend.coverage_caveats())
    elif settings.backend in ("windows", "windows-replay"):
        from .backends.windows import build_windows_backend
        from .errors import safe_error
        try:
            backend = build_windows_backend(settings)
        except Exception as exc:  # noqa: BLE001
            kind, msg = safe_error(exc)
            rows.append({"check": "windows event log backend", "ok": False, "kind": kind, "detail": msg})
        else:
            rows.extend(backend.probe())
            rows.extend({"check": "caveat", "ok": True, "kind": None, "detail": c}
                        for c in backend.coverage_caveats())
    else:
        rows.append({"check": "fixture backend", "ok": True, "kind": None,
                     "detail": f"{settings.cases_dir} (synthetic telemetry)"})
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            mark = "OK  " if r["ok"] else "FAIL"
            kind = f" [{r['kind']}]" if r.get("kind") else ""
            print(f"{mark} {r['check']}{kind}: {r['detail']}")
    return 0 if all(r["ok"] for r in rows if r["check"] != "caveat") else 1


def cmd_sources(args: argparse.Namespace) -> int:
    """Capability discovery for the Windows event log backends."""
    settings = _settings_from_args(args)
    if settings.backend not in ("windows", "windows-replay"):
        print(f"backend={settings.backend}: telemetry-source discovery applies to the windows backends "
              "(use --backend windows).")
        return 0
    from .backends.windows import build_windows_backend
    from .errors import safe_error
    try:
        backend = build_windows_backend(settings)
    except Exception as exc:  # noqa: BLE001
        kind, msg = safe_error(exc)
        print(f"FAIL [{kind}] {msg}")
        return 1
    statuses = backend.source_status()
    facts = backend.reader.host_facts()
    backend.list_alerts()
    if args.json:
        print(json.dumps({"host": backend.primary_host(), "facts": facts,
                          "sources": [s.model_dump() for s in statuses],
                          "signal_notes": backend.signal_notes}, indent=2))
    else:
        marks = {"active": "✓", "limited": "⚠", "not_installed": "○", "access_denied": "✗", "error": "✗"}
        print(f"Telemetry sources on {backend.primary_host()} (reader: {backend.reader.name}; "
              f"elevated: {facts.get('elevated', 'unknown')})")
        for st in statuses:
            print(f"  {marks[st.state]} {st.label:<20} {st.state.replace('_', ' '):<14} {st.detail}")
        for note in backend.signal_notes:
            print(f"  note: {note}")
    return 0 if all(s.state == "active" for s in statuses) else 2


def cmd_acceptance(args: argparse.Namespace) -> int:
    """v0.3.1 behavior-based acceptance on the demo fixtures (run with --llm ollama)."""
    from .evaluation.acceptance import format_acceptance, run_acceptance

    settings = _settings_from_args(args)
    result = run_acceptance(settings, args.alerts or ["INC-001", "INC-002", "INC-003", "INC-004", "INC-005"],
                            repeats=args.repeats, out_dir=args.out)
    print(json.dumps(result, indent=2, default=str) if args.json else format_acceptance(result))
    return 0 if result["all_passed"] else 3


def cmd_benchmark(args: argparse.Namespace) -> int:
    from .evaluation.benchmark import format_benchmark, run_benchmark

    settings = _settings_from_args(args)
    result = run_benchmark(settings, suite_dir=args.suite, adversary=args.adversary, repeats=args.repeats)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(format_benchmark(result))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, default=str)
    # A benchmark measures; it "fails" when the harness itself could not run, or
    # when an adversarial model obtained benign closure of a non-benign case.
    if result["metrics"]["operational"]["harness_errors"]:
        return 1
    if args.adversary and result["metrics"]["integrity"]["benign_false_positive"]:
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="investigator", description="Investigator — local-first AI security "
                                "investigation agent for Windows")
    p.add_argument("--llm", choices=["mock", "ollama"])
    p.add_argument("--backend", choices=["fixture", "windows", "windows-replay", "wazuh"])
    p.add_argument("--replay-dir", help="recorded Windows event XML directory (backend windows-replay)")
    p.add_argument("--max-steps", type=int)
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("serve", help="launch the web dashboard")
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("list", help="list alerts")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("investigate", help="run one investigation")
    sp.add_argument("alert_id")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--markdown", action="store_true")
    sp.add_argument("--quiet", action="store_true")
    sp.add_argument("--out", help="write report to a .json or .md file")
    sp.set_defaults(func=cmd_investigate)

    sp = sub.add_parser("evaluate", help="run all fixtures through the evaluator")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_evaluate)

    sp = sub.add_parser("health", help="check ollama/backend wiring")
    sp.set_defaults(func=cmd_health)

    sp = sub.add_parser("diagnose", help="read-only checks of the live model and backend (lab bring-up)")
    sp.add_argument("--host", help="agent/host name to check for Sysmon telemetry")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_diagnose)

    sp = sub.add_parser("sources", help="show telemetry sources and access on this computer (windows backends)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_sources)

    sp = sub.add_parser("benchmark", help="run the independent benchmark suite and report separated metrics")
    sp.add_argument("--suite", help="benchmark suite directory (default: packaged independent suite)")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--out", help="also write the JSON result to this file")
    sp.add_argument("--adversary", choices=["benign-after-investigation", "benign-immediately"],
                    help="replace the model with an evaluation-only benign proposer to test the verdict gates")
    sp.add_argument("--repeats", type=int, default=1, help="run every case N times (real models vary)")
    sp.set_defaults(func=cmd_benchmark)

    sp = sub.add_parser("acceptance", help="v0.3.1 behavior-based acceptance on the demo fixtures "
                                           "(use --llm ollama)")
    sp.add_argument("--alerts", nargs="*", help="alert ids (default: INC-001..INC-005)")
    sp.add_argument("--repeats", type=int, default=1)
    sp.add_argument("--out", help="directory for per-run JSON/Markdown reports and acceptance.json")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_acceptance)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        # default: serve
        args.func = cmd_serve
        args.command = "serve"
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
