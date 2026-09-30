"""Command-line entry point.

    python -m investigator serve           # launch the web dashboard
    python -m investigator list            # list alerts in the current backend
    python -m investigator investigate INC-001   # run one investigation, print report
    python -m investigator evaluate        # run all fixtures through the evaluator
    python -m investigator health          # check Ollama / backend wiring

Flags: --llm mock|ollama  --backend fixture|wazuh  --max-steps N
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
    return load_settings(**overrides)


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = _settings_from_args(args)
    print(f"SOC Investigation Agent — llm={settings.llm} backend={settings.backend} "
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
        print(f"backend: FAIL — {exc}")
        return 1
    return 0 if healthy else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="investigator", description="Local-first SOC Investigation Agent")
    p.add_argument("--llm", choices=["mock", "ollama"])
    p.add_argument("--backend", choices=["fixture", "wazuh"])
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
