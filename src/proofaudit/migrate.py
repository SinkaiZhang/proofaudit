from __future__ import annotations

from pathlib import Path
from typing import Any

from .io import load_data, sha256_file, write_json


PLUGIN_MAP = {
    "source_repro.capture": "source.capture",
    "claim_normalize.structure": "claim.normalize",
    "semantic_bridge.mapping": "semantic.bridge",
    "obligation_graph.coverage": "obligation.coverage",
    "dependency_trust.audit": "dependency.trust",
    "evidence_router.plan": "evidence.route",
    "witness_falsification.audit": "witness.audit",
    "independent_reproduction.audit": "reproduction.audit",
    "governance.final_gate": "governance.final",
}


def migrate_legacy(
    claim_path: str | Path,
    pipeline_path: str | Path,
    output_dir: str | Path,
    plugin_manifests: list[str] | None = None,
) -> Path:
    old_claim_path = Path(claim_path).expanduser().resolve()
    old_pipeline_path = Path(pipeline_path).expanduser().resolve()
    old_claim = load_data(old_claim_path)
    old_pipeline = load_data(old_pipeline_path)
    metadata = old_claim.get("metadata", {})
    output = Path(output_dir).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=False)
    source_records = []
    source_ids = []
    expected = metadata.get("source_sha256", {})
    for index, raw in enumerate(old_claim.get("sources", []), start=1):
        source = (old_claim_path.parent / raw).resolve()
        source_id = f"source-{index}"
        source_ids.append(source_id)
        source_records.append({
            "id": source_id,
            "path": str(raw).replace("\\", "/"),
            "sha256": str(expected.get(raw) or (sha256_file(source) if source.is_file() else "0" * 64)).upper(),
            "media_type": "application/octet-stream",
            "redistributable": False,
        })
    graph = metadata.get("obligation_graph", {"coverage_status": "INITIAL", "nodes": [], "edges": []})
    normalized_nodes = []
    for node in graph.get("nodes", []):
        raw_types = node.get("evidence_type", [])
        evidence_types = [raw_types] if isinstance(raw_types, str) else list(raw_types)
        normalized_nodes.append({
            "id": node["id"],
            "type": node.get("type", "lemma"),
            "statement": node.get("statement", node["id"]),
            "required": bool(node.get("required", True)),
            "evidence_types": evidence_types,
            "source_refs": list(node.get("source_refs", source_ids[:1] or ["migration-note"])),
        })
    bridge = metadata.get("semantic_bridge", {})
    bridge_path = bridge.get("bridge_file") if isinstance(bridge, dict) else bridge
    new_claim = {
        "schema_version": "0.1",
        "claim_id": old_claim["claim_id"],
        "title": old_claim["title"],
        "statement": old_claim.get("raw_statement", "Legacy claim"),
        "domain": old_claim.get("domain", "unspecified"),
        "assumptions": old_claim.get("assumptions", []),
        "conclusion_type": old_claim.get("conclusion_type", "theorem"),
        "sources": source_ids,
        "semantic_bridge": {
            "path": bridge_path or "semantic_bridge.json",
            "status": bridge.get("status", "UNVERIFIED") if isinstance(bridge, dict) else "UNVERIFIED",
        },
        "obligation_graph": {
            "coverage_status": graph.get("coverage_status", "INITIAL"),
            "completeness_note": graph.get("completeness_note", "Migrated; requires review."),
            "nodes": normalized_nodes,
            "edges": graph.get("edges", []),
        },
        "dependencies": [
            {**item, "audit_status": item.get("audit_status", "UNVERIFIED")}
            for item in metadata.get("dependencies", [])
        ],
    }
    stages = []
    for stage in old_pipeline.get("stages", []):
        stages.append({
            "id": stage["id"],
            "plugin": PLUGIN_MAP.get(stage["plugin"], stage["plugin"]),
            "required": bool(stage.get("required", False)),
            "config": stage.get("config", {}),
        })
    new_pipeline = {
        "schema_version": "0.1",
        "name": old_pipeline.get("name", "migrated-pipeline"),
        "description": old_pipeline.get("description", "Migrated legacy pipeline"),
        "strict": True,
        "timeout_seconds": old_pipeline.get("defaults", {}).get("global_timeout_seconds", 10800),
        "assurance_requirements": {"source": "VERIFIED", "semantic": "VERIFIED"},
        "stages": stages,
    }
    case = {
        "schema_version": "0.1",
        "case_id": old_claim["claim_id"],
        "claim": "claim.json",
        "pipeline": "pipeline.json",
        "source_lock": "sources.lock.json",
        "plugin_manifests": plugin_manifests or [],
    }
    write_json(output / "case.json", case)
    write_json(output / "claim.json", new_claim)
    write_json(output / "pipeline.json", new_pipeline)
    write_json(output / "sources.lock.json", {
        "schema_version": "0.1",
        "case_id": old_claim["claim_id"],
        "sources": source_records,
    })
    (output / "MIGRATION.md").write_text(
        "# Migration review required\n\nThis conversion is structural only. Review paths, plugin IDs, semantic status, dependencies, evidence routes, and source licenses before running.\n",
        encoding="utf-8",
    )
    return output / "case.json"

