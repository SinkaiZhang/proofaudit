from __future__ import annotations

import importlib.util
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .engine import run_audit, validate_case
from .io import load_data, resolve_within, sha256_file, write_json
from .validation import validate_document


Materializer = Callable[..., dict[str, Any] | None]


def _load_materializer(module_path: Path, callable_name: str) -> Materializer:
    module_name = f"proofaudit_test_fixture_{sha256_file(module_path)[:16].lower()}"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load test fixture module: {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(module_path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    materializer = getattr(module, callable_name, None)
    if not callable(materializer):
        raise ValueError(
            f"test fixture callable {callable_name!r} is absent from {module_path}"
        )
    return materializer


def _closure_counts(stage: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for closure in stage.get("evidence_closures", []):
        evidence_type = str(closure.get("evidence_type", ""))
        counts[evidence_type] = counts.get(evidence_type, 0) + 1
    return counts


def _assert_complete_run(trace: dict[str, Any], contract: dict[str, Any]) -> dict[str, Any]:
    stages = {stage["stage_id"]: stage for stage in trace.get("stages", [])}
    non_pass = {
        stage_id: stage.get("status")
        for stage_id, stage in stages.items()
        if stage.get("status") != "PASS"
    }
    if not stages or non_pass:
        raise ValueError(f"TEST_ONLY pipeline has non-PASS stages: {non_pass}")
    if trace.get("decision") != "PASS":
        raise ValueError(f"TEST_ONLY governance decision is {trace.get('decision')!r}, not PASS")

    governance_stage_id = contract["governance_stage"]
    governance = stages.get(governance_stage_id)
    if governance is None:
        raise ValueError(f"governance stage is absent: {governance_stage_id}")
    if governance.get("decision") != "PASS":
        raise ValueError(
            f"governance stage decision is {governance.get('decision')!r}, not PASS"
        )
    open_requirements = governance.get("evidence_manifest", {}).get("open_requirements", [])
    if open_requirements:
        raise ValueError(f"governance left open requirements: {open_requirements}")

    observed_assurance = {
        name: trace.get("assurance_profile", {}).get(name, {}).get("level")
        for name in contract["expected_assurance_levels"]
    }
    if observed_assurance != contract["expected_assurance_levels"]:
        raise ValueError(
            "assurance mismatch: "
            f"expected={contract['expected_assurance_levels']}, observed={observed_assurance}"
        )

    observed_stage_closures: dict[str, dict[str, int]] = {}
    for stage_id, expected in contract.get("expected_stage_closures", {}).items():
        stage = stages.get(stage_id)
        if stage is None:
            raise ValueError(f"closure assertion stage is absent: {stage_id}")
        all_counts = _closure_counts(stage)
        observed = {evidence_type: all_counts.get(evidence_type, 0) for evidence_type in expected}
        if observed != expected:
            raise ValueError(
                f"closure mismatch at {stage_id}: expected={expected}, observed={observed}"
            )
        observed_stage_closures[stage_id] = observed

    return {
        "stage_statuses": {stage_id: stage["status"] for stage_id, stage in stages.items()},
        "assurance_levels": observed_assurance,
        "stage_closure_counts": observed_stage_closures,
        "governance_open_requirements": [],
    }


def run_test_e2e(
    case_path: str | Path,
    output_path: str | Path,
    *,
    timeout_ms: int | None = None,
) -> dict[str, Any]:
    """Run a case-provided synthetic fixture through the production audit engine."""
    loaded = validate_case(case_path)
    contract_ref = loaded.case.get("test_e2e")
    if not contract_ref:
        raise ValueError("case does not declare a test_e2e contract")
    contract_path = resolve_within(loaded.root, contract_ref)
    contract = load_data(contract_path)
    validate_document(contract, "test-e2e.v0.1.schema.json")
    module_path = resolve_within(loaded.root, contract["materializer"]["module"])
    materializer = _load_materializer(module_path, contract["materializer"]["callable"])
    relative_case_path = loaded.case_path.relative_to(loaded.root)
    output = Path(output_path).expanduser().resolve()

    persisted: dict[str, Any]
    with tempfile.TemporaryDirectory(prefix="proofaudit-test-e2e-") as raw:
        ephemeral_root = Path(raw)
        target_case_root = ephemeral_root / "case"
        materializer(
            source_case_root=loaded.root,
            target_case_root=target_case_root,
            ephemeral_root=ephemeral_root,
        )
        target_case_path = target_case_root / relative_case_path
        if not target_case_path.is_file():
            raise ValueError(f"materializer did not create the case file: {target_case_path}")
        artifact_root = ephemeral_root / "artifacts"
        trace = run_audit(target_case_path, artifact_root, timeout_ms=timeout_ms)
        assertions = _assert_complete_run(trace, contract)
        raw_trace = artifact_root / trace["case_id"] / "audit_trace.json"
        persisted = {
            "schema_version": "test-e2e-result.v0.1",
            "status": "VERIFIED_TEST_ONLY",
            "non_adjudicative": True,
            "production_verdict_suppressed": True,
            "ephemeral_engine_decision": trace["decision"],
            "ephemeral_fixture_destroyed": True,
            "ephemeral_raw_trace_destroyed": True,
            "case_id": trace["case_id"],
            "test_contract_sha256": sha256_file(contract_path),
            "materializer_sha256": sha256_file(module_path),
            "audit_trace_sha256": sha256_file(raw_trace),
            "stage_count": len(trace["stages"]),
            "elapsed_ms": trace["elapsed_ms"],
            **assertions,
        }

    write_json(output, persisted)
    return persisted
