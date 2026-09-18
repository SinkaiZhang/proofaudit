from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import run_audit, validate_case
from .migrate import migrate_legacy
from .packing import pack_case
from .report import render_report
from .test_e2e import run_test_e2e


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proofaudit")
    parser.add_argument("--version", action="version", version="proofaudit 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="Validate a case contract without running it")
    validate.add_argument("--case", required=True)

    run = commands.add_parser("run", help="Run a fail-closed audit")
    run.add_argument("--case", required=True)
    run.add_argument("--artifact-dir", required=True)
    run.add_argument("--timeout-ms", type=int)

    test_e2e = commands.add_parser(
        "test-e2e",
        help="Run a case-provided non-adjudicative fixture through the full pipeline",
    )
    test_e2e.add_argument("--case", required=True)
    test_e2e.add_argument("--output", required=True)
    test_e2e.add_argument("--timeout-ms", type=int)

    report = commands.add_parser("report", help="Render a portable HTML audit report")
    report.add_argument("--trace", required=True)
    report.add_argument("--output", required=True)

    pack = commands.add_parser("pack", help="Create a deterministic redistributable case bundle")
    pack.add_argument("--case", required=True)
    pack.add_argument("--output", required=True)

    migrate = commands.add_parser("migrate-legacy", help="Convert a legacy v2 case to v0.1")
    migrate.add_argument("--claim", required=True)
    migrate.add_argument("--pipeline", required=True)
    migrate.add_argument("--output-dir", required=True)
    migrate.add_argument("--plugin-manifest", action="append", default=[])
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "validate":
            loaded = validate_case(args.case)
            payload = {"status": "ok", "case_id": loaded.case["case_id"]}
        elif args.command == "run":
            payload = run_audit(args.case, args.artifact_dir, timeout_ms=args.timeout_ms)
        elif args.command == "test-e2e":
            payload = run_test_e2e(args.case, args.output, timeout_ms=args.timeout_ms)
        elif args.command == "report":
            output = render_report(args.trace, args.output)
            payload = {"status": "ok", "output": str(output)}
        elif args.command == "pack":
            output = pack_case(args.case, args.output)
            payload = {"status": "ok", "output": str(output)}
        elif args.command == "migrate-legacy":
            output = migrate_legacy(
                args.claim,
                args.pipeline,
                args.output_dir,
                args.plugin_manifest,
            )
            payload = {"status": "ok", "case": str(output)}
        else:
            raise ValueError(f"unsupported command: {args.command}")
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({
            "status": "error",
            "code": "PROOFAUDIT_ERROR",
            "exception_type": type(exc).__name__,
            "detail": str(exc),
        }, ensure_ascii=False, indent=2))
        return 2
