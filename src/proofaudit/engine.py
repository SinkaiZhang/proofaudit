from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .assurance import derive_profile, serialize_profile
from .io import load_data, resolve_within, sha256_file, write_json
from .manifests import load_plugins, merge_manifests
from .models import (
    ClaimBundle,
    ClaimVerdict,
    EvidenceAssurance,
    EvidenceClosure,
    Finding,
    PluginResult,
    StageContext,
    Status,
    Verdict,
    failure,
    serialize,
)
from .validation import validate_document


@dataclass(frozen=True)
class LoadedCase:
    case_path: Path
    root: Path
    case: dict[str, Any]
    claim: dict[str, Any]
    pipeline: dict[str, Any]
    source_lock: dict[str, Any]
    overlay_manifests: tuple[Path, ...]


def validate_case(case_path: str | Path) -> LoadedCase:
    path = Path(case_path).expanduser().resolve()
    case = load_data(path)
    validate_document(case, "case-spec.v0.1.schema.json")
    root = path.parent
    claim_path = resolve_within(root, case["claim"])
    pipeline_path = resolve_within(root, case["pipeline"])
    lock_path = resolve_within(root, case["source_lock"])
    claim = load_data(claim_path)
    pipeline = load_data(pipeline_path)
    source_lock = load_data(lock_path)
    validate_document(claim, "claim-bundle.v0.1.schema.json")
    validate_document(pipeline, "pipeline.v0.1.schema.json")
    validate_document(source_lock, "source-lock.v0.1.schema.json")
    if case["case_id"] != claim["claim_id"] or case["case_id"] != source_lock["case_id"]:
        raise ValueError("case_id, claim_id, and source-lock case_id must match")
    overlays = tuple(resolve_within(root, item) for item in case.get("plugin_manifests", []))
    for manifest in overlays:
        validate_document(load_data(manifest), "plugin-manifest.v0.1.schema.json")
    source_ids = {item["id"] for item in source_lock["sources"]}
    missing_sources = sorted(set(claim["sources"]) - source_ids)
    if missing_sources:
        raise ValueError(f"claim sources are absent from source lock: {missing_sources}")
    return LoadedCase(path, root, case, claim, pipeline, source_lock, overlays)


def run_audit(
    case_path: str | Path,
    artifact_dir: str | Path,
    *,
    timeout_ms: int | None = None,
) -> dict[str, Any]:
    loaded = validate_case(case_path)
    manifest = merge_manifests(loaded.overlay_manifests)
    entries = {entry["id"]: entry for entry in manifest["plugins"]}
    plugins = load_plugins(manifest)
    claim = ClaimBundle.from_dict(loaded.claim)
    target = Path(artifact_dir).expanduser().resolve() / loaded.case["case_id"]
    target.mkdir(parents=True, exist_ok=True)
    results: list[PluginResult] = []
    seen_stages = set()
    failed_required_stages: list[str] = []
    started = time.perf_counter()
    for stage in loaded.pipeline["stages"]:
        stage_id = stage["id"]
        plugin_id = stage["plugin"]
        if stage_id in seen_stages:
            raise ValueError(f"duplicate stage id: {stage_id}")
        seen_stages.add(stage_id)
        if failed_required_stages and stage.get("skip_on_required_failure", False):
            results.append(PluginResult(
                stage_id=stage_id,
                plugin_id=plugin_id,
                status=Status.SKIP,
                risk_level="HIGH",
                residual_risks=[
                    "Stage was not executed because a required prerequisite gate failed."
                ],
                evidence_manifest={
                    "skip_reason": "required_stage_failure",
                    "blocked_by": list(failed_required_stages),
                },
                runtime_ms=0,
            ))
            continue
        if plugin_id not in entries:
            result = failure(
                stage_id,
                plugin_id,
                "PLUGIN_NOT_REGISTERED",
                "plugin_not_registered",
                f"Plugin {plugin_id} is absent from the merged manifest.",
            )
            results.append(result)
            if stage.get("required"):
                failed_required_stages.append(stage_id)
            continue
        plugin_class = plugins.get(plugin_id)
        if plugin_class is None:
            result = failure(
                stage_id,
                plugin_id,
                "PLUGIN_NOT_LOADABLE",
                "plugin_not_loadable",
                f"Plugin {plugin_id} could not be loaded.",
            )
            results.append(result)
            if stage.get("required"):
                failed_required_stages.append(stage_id)
            continue
        context = StageContext(
            stage_id=stage_id,
            claim=claim,
            case=loaded.case,
            pipeline=loaded.pipeline,
            plugin_manifest=manifest,
            source_lock=loaded.source_lock,
            prior_results=list(results),
            case_root=loaded.root,
            artifact_dir=target,
        )
        stage_started = time.perf_counter()
        try:
            result = plugin_class().run(context, dict(stage.get("config", {})))
        except Exception as exc:
            result = failure(
                stage_id,
                plugin_id,
                "PLUGIN_EXECUTION_ERROR",
                "plugin_execution_error",
                f"{type(exc).__name__}: {exc}",
            )
        result.stage_id = stage_id
        result.plugin_id = plugin_id
        result.runtime_ms = int((time.perf_counter() - stage_started) * 1000)
        result = _enforce_contract(result, entries[plugin_id], claim)
        results.append(result)
        if stage.get("required") and result.status == Status.FAIL:
            failed_required_stages.append(stage_id)
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    serialized_results = [serialize(result) for result in results]
    decision = _derive_decision(results)
    if timeout_ms is not None and elapsed_ms > timeout_ms:
        decision = Verdict.REQUIRES_REVIEW
    profile = derive_profile(results)
    summary = {
        "total": len(results),
        "pass": sum(result.status == Status.PASS for result in results),
        "warn": sum(result.status == Status.WARN for result in results),
        "fail": sum(result.status == Status.FAIL for result in results),
        "skip": sum(result.status == Status.SKIP for result in results),
        "verified": sum(
            result.assurance == EvidenceAssurance.VERIFIED for result in results
        ),
        "critical_findings": [
            serialize(finding)
            for result in results
            for finding in result.findings
            if finding.severity in {"P0", "P1"}
        ],
    }
    trace = {
        "schema_version": "0.1",
        "status": "ok",
        "case_id": loaded.case["case_id"],
        "claim_title": claim.title,
        "decision": decision.value,
        "assurance_profile": serialize_profile(profile),
        "elapsed_ms": elapsed_ms,
        "summary": summary,
        "stages": serialized_results,
        "inputs": {
            "case_sha256": sha256_file(loaded.case_path),
            "claim_sha256": sha256_file(resolve_within(loaded.root, loaded.case["claim"])),
            "pipeline_sha256": sha256_file(resolve_within(loaded.root, loaded.case["pipeline"])),
            "source_lock_sha256": sha256_file(
                resolve_within(loaded.root, loaded.case["source_lock"])
            ),
            "plugin_manifests": manifest["manifest_sources"],
        },
        "timeout": {
            "limit_ms": timeout_ms,
            "observed_exceeded": timeout_ms is not None and elapsed_ms > timeout_ms,
        },
    }
    write_json(target / "audit_trace.json", trace)
    return trace


def _enforce_contract(
    result: PluginResult,
    entry: dict[str, Any],
    claim: ClaimBundle,
) -> PluginResult:
    if not isinstance(result, PluginResult):
        return failure(
            "unknown",
            entry["id"],
            "PLUGIN_CONTRACT_VIOLATION",
            "invalid_plugin_result",
            "Plugin did not return PluginResult.",
        )
    if (result.evidence_closures or result.claim_verdict) and (
        result.status != Status.PASS or result.assurance != EvidenceAssurance.VERIFIED
    ):
        return failure(
            result.stage_id,
            result.plugin_id,
            "UNVERIFIED_EVIDENCE_CLOSURE",
            "unverified_evidence_closure",
            "Only PASS + VERIFIED results may close evidence or emit a claim verdict.",
        )
    if entry["role"] == "evidence_adapter" and result.status == Status.PASS:
        if result.assurance == EvidenceAssurance.VERIFIED and not (
            result.evidence_closures or result.claim_verdict
        ):
            return failure(
                result.stage_id,
                result.plugin_id,
                "EMPTY_ADAPTER_RESULT",
                "verified_adapter_closed_nothing",
                "A verified adapter must emit a typed closure or terminal claim verdict.",
            )
    nodes = {node["id"]: node for node in claim.obligation_graph["nodes"]}
    seen = set()
    allowed_types = set(entry.get("evidence_types", []))
    issues = []
    for closure in result.evidence_closures:
        if not isinstance(closure, EvidenceClosure):
            issues.append("closure is not an EvidenceClosure")
            continue
        key = (closure.obligation_id, closure.evidence_type, closure.adapter_id)
        if key in seen:
            issues.append(f"duplicate closure: {key}")
        seen.add(key)
        node = nodes.get(closure.obligation_id)
        if node is None or not node.get("required", True):
            issues.append(f"unknown or optional obligation: {closure.obligation_id}")
        elif closure.evidence_type not in node["evidence_types"]:
            issues.append(f"unexpected evidence type: {closure.evidence_type}")
        if allowed_types and closure.evidence_type not in allowed_types:
            issues.append(f"adapter does not declare type: {closure.evidence_type}")
        if closure.adapter_id != result.plugin_id:
            issues.append("closure adapter_id does not match executing plugin")
        if len(closure.artifact.sha256) != 64:
            issues.append("artifact SHA-256 is malformed")
        if not closure.verification_method.strip():
            issues.append("verification method is empty")
    if issues:
        return failure(
            result.stage_id,
            result.plugin_id,
            "INVALID_EVIDENCE_CLOSURE",
            "invalid_evidence_closure",
            "; ".join(issues),
        )
    return result


def _derive_decision(results: list[PluginResult]) -> Verdict:
    gate = next(
        (result for result in reversed(results) if result.plugin_id == "governance.final"),
        None,
    )
    if gate and gate.assurance == EvidenceAssurance.VERIFIED and gate.decision:
        return gate.decision
    return Verdict.REQUIRES_REVIEW
