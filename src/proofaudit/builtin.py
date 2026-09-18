from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from .assurance import derive_profile, serialize_profile, unmet_requirements
from .io import canonical_sha256, resolve_within, sha256_file
from .models import (
    ArtifactRef,
    AssuranceDimension,
    AssuranceLevel,
    ClaimVerdict,
    DimensionAssessment,
    EvidenceAssurance,
    Finding,
    Plugin,
    PluginResult,
    Status,
    Verdict,
)


def _required_slots(context) -> set[tuple[str, str]]:
    slots = set()
    for node in context.claim.obligation_graph.get("nodes", []):
        if not node.get("required", True):
            continue
        for evidence_type in node.get("evidence_types", []):
            slots.add((str(node["id"]), str(evidence_type)))
    return slots


class SourceCapturePlugin(Plugin):
    plugin_id = "source.capture"
    layer = "L0"

    def run(self, context, config):
        entries = context.source_lock.get("sources", [])
        if not entries:
            return _gate_failure(context, self.plugin_id, "SOURCE_SET_EMPTY", "No sources are locked.")
        findings = []
        artifacts = {}
        observed_ids = set()
        reference_ids = set()
        for entry in entries:
            source_id = str(entry["id"])
            observed_ids.add(source_id)
            source_kind = str(entry.get("kind", "source_payload"))
            if source_kind == "reference_metadata":
                reference_ids.add(source_id)
            path = resolve_within(context.case_root, entry["path"])
            actual = sha256_file(path)
            artifacts[source_id] = ArtifactRef(
                uri=path.relative_to(context.case_root).as_posix(),
                sha256=actual,
                generated_by=self.plugin_id,
                media_type=entry.get("media_type", "application/octet-stream"),
            )
            if actual != entry["sha256"].upper():
                findings.append(Finding(
                    code="SOURCE_HASH_MISMATCH",
                    title="source_changed_since_lock",
                    severity="P0",
                    detail=f"Hash mismatch for source {source_id}.",
                    evidence=[source_id, f"expected={entry['sha256']}", f"actual={actual}"],
                ))
        missing_ids = sorted(set(context.claim.sources) - observed_ids)
        if missing_ids:
            findings.append(Finding(
                code="SOURCE_LOCK_INCOMPLETE",
                title="claim_source_not_locked",
                severity="P0",
                detail="Claim sources are absent from sources.lock.json.",
                evidence=missing_ids,
            ))
        if findings:
            return PluginResult(
                stage_id=context.stage_id,
                plugin_id=self.plugin_id,
                status=Status.FAIL,
                risk_level="CRITICAL",
                assurance=EvidenceAssurance.VERIFIED,
                findings=findings,
                artifacts=artifacts,
            )
        source_level = (
            AssuranceLevel.ASSERTED if reference_ids else AssuranceLevel.VERIFIED
        )
        residual_risks = (
            [
                "Reference metadata was hash-verified, but the referenced external payloads "
                "were not present and verified in this run."
            ]
            if reference_ids else []
        )
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.PASS,
            risk_level="MEDIUM" if reference_ids else "LOW",
            assurance=EvidenceAssurance.VERIFIED,
            artifacts=artifacts,
            residual_risks=residual_risks,
            evidence_manifest={
                "payload_sources": sorted(observed_ids - reference_ids),
                "reference_metadata_sources": sorted(reference_ids),
            },
            assurance_contributions={
                AssuranceDimension.SOURCE: DimensionAssessment(
                    level=source_level,
                    evidence=tuple(sorted(observed_ids)),
                    residual_risks=tuple(residual_risks),
                )
            },
        )


class ClaimNormalizePlugin(Plugin):
    plugin_id = "claim.normalize"
    layer = "L1"

    def run(self, context, config):
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.PASS,
            risk_level="LOW",
            assurance=EvidenceAssurance.VERIFIED,
            evidence_manifest={
                "claim_id": context.claim.claim_id,
                "assumption_count": len(context.claim.assumptions),
                "conclusion_type": context.claim.conclusion_type,
            },
        )


class SemanticBridgePlugin(Plugin):
    plugin_id = "semantic.bridge"
    layer = "L2"

    def run(self, context, config):
        bridge = context.claim.semantic_bridge
        path = resolve_within(context.case_root, bridge["path"])
        digest = sha256_file(path)
        declared = bridge.get("sha256")
        if declared and digest != str(declared).upper():
            return _gate_failure(
                context,
                self.plugin_id,
                "SEMANTIC_BRIDGE_HASH_MISMATCH",
                "The semantic bridge changed after the claim was frozen.",
            )
        status = bridge["status"]
        level = AssuranceLevel.VERIFIED if status == "VERIFIED" else AssuranceLevel.ASSERTED
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.PASS,
            risk_level="LOW" if status == "VERIFIED" else "MEDIUM",
            assurance=EvidenceAssurance.VERIFIED,
            artifacts={
                "semantic_bridge": ArtifactRef(
                    uri=path.relative_to(context.case_root).as_posix(),
                    sha256=digest,
                    generated_by=self.plugin_id,
                )
            },
            residual_risks=([] if status == "VERIFIED" else [
                "The bridge artifact is pinned but its semantic equivalence is not independently verified."
            ]),
            assurance_contributions={
                AssuranceDimension.SEMANTIC: DimensionAssessment(
                    level=level,
                    evidence=(path.relative_to(context.case_root).as_posix(),),
                    residual_risks=(() if status == "VERIFIED" else (
                        "Semantic equivalence remains asserted.",
                    )),
                )
            },
        )


class ObligationCoveragePlugin(Plugin):
    plugin_id = "obligation.coverage"
    layer = "L3"

    def run(self, context, config):
        graph = context.claim.obligation_graph
        nodes = graph["nodes"]
        node_ids = {node["id"] for node in nodes}
        indegree = {node_id: 0 for node_id in node_ids}
        outgoing: dict[str, list[str]] = defaultdict(list)
        for edge in graph.get("edges", []):
            source, target = edge["from"], edge["to"]
            if source not in node_ids or target not in node_ids:
                return _gate_failure(
                    context,
                    self.plugin_id,
                    "OBLIGATION_DANGLING_EDGE",
                    f"Unknown obligation edge: {source} -> {target}",
                )
            outgoing[source].append(target)
            indegree[target] += 1
        queue = deque(sorted(node for node, degree in indegree.items() if degree == 0))
        visited = 0
        while queue:
            source = queue.popleft()
            visited += 1
            for target in outgoing[source]:
                indegree[target] -= 1
                if indegree[target] == 0:
                    queue.append(target)
        if visited != len(node_ids):
            return _gate_failure(
                context,
                self.plugin_id,
                "OBLIGATION_GRAPH_CYCLE",
                "The obligation graph is not acyclic.",
            )
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.PASS,
            risk_level="LOW",
            assurance=EvidenceAssurance.VERIFIED,
            evidence_manifest={
                "node_count": len(nodes),
                "edge_count": len(graph.get("edges", [])),
                "graph_sha256": canonical_sha256(graph),
                "semantic_completeness_asserted": False,
            },
            residual_risks=[
                "DAG validation does not prove that the obligation decomposition is semantically complete."
            ],
        )


class DependencyTrustPlugin(Plugin):
    plugin_id = "dependency.trust"
    layer = "L4"

    def run(self, context, config):
        dependencies = list(context.claim.dependencies)
        if not dependencies and not config.get("allow_empty", False):
            return _gate_failure(
                context,
                self.plugin_id,
                "DEPENDENCY_SET_EMPTY",
                "No trusted dependencies were declared.",
            )
        mode = str(config.get("mode", "static"))
        if mode == "pinning":
            unpinned = [
                item["id"] for item in dependencies
                if not str(item.get("version", "")).strip()
                or str(item.get("version", "")).lower() in {"latest", "main", "master", "head"}
            ]
            if unpinned:
                return _gate_failure(
                    context,
                    self.plugin_id,
                    "DEPENDENCY_UNPINNED",
                    "Dependencies lack immutable version identifiers: " + ", ".join(unpinned),
                )
            return PluginResult(
                stage_id=context.stage_id,
                plugin_id=self.plugin_id,
                status=Status.PASS,
                risk_level="LOW",
                assurance=EvidenceAssurance.VERIFIED,
                evidence_manifest={
                    "mode": "pinning",
                    "pinned_dependencies": [
                        {"id": item["id"], "version": item["version"]}
                        for item in dependencies
                    ],
                    "runtime_trust_asserted": False,
                },
                residual_risks=[
                    "Version pinning does not establish that dependencies were exercised successfully."
                ],
            )
        if mode == "attestation":
            runtime_verified = {
                dependency
                for result in context.prior_results
                if result.status == Status.PASS
                and result.assurance == EvidenceAssurance.VERIFIED
                for dependency in result.trusted_dependencies
            }
            closed = {
                item["id"] for item in dependencies
                if item.get("audit_status") == "VERIFIED" or item["id"] in runtime_verified
            }
            open_dependencies = sorted(
                item["id"] for item in dependencies if item["id"] not in closed
            )
            if open_dependencies:
                return _gate_failure(
                    context,
                    self.plugin_id,
                    "DEPENDENCY_ATTESTATION_MISSING",
                    "No current-run verified adapter attested dependencies: "
                    + ", ".join(open_dependencies),
                )
            return PluginResult(
                stage_id=context.stage_id,
                plugin_id=self.plugin_id,
                status=Status.PASS,
                risk_level="LOW",
                assurance=EvidenceAssurance.VERIFIED,
                trusted_dependencies=sorted(closed),
                evidence_manifest={
                    "mode": "attestation",
                    "runtime_attestations": sorted(runtime_verified),
                    "closed_dependencies": sorted(closed),
                },
            )
        if mode != "static":
            return _gate_failure(
                context,
                self.plugin_id,
                "DEPENDENCY_MODE_INVALID",
                f"Unsupported dependency trust mode: {mode}",
            )
        open_dependencies = [
            item["id"] for item in dependencies if item.get("audit_status") != "VERIFIED"
        ]
        if open_dependencies:
            return _gate_failure(
                context,
                self.plugin_id,
                "DEPENDENCY_UNVERIFIED",
                "Required dependencies remain unverified: " + ", ".join(open_dependencies),
            )
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.PASS,
            risk_level="LOW",
            assurance=EvidenceAssurance.VERIFIED,
            trusted_dependencies=[item["id"] for item in dependencies],
        )


class EvidenceRoutePlugin(Plugin):
    plugin_id = "evidence.route"
    layer = "L5"

    def run(self, context, config):
        routes = config.get("routes", {})
        entries = {entry["id"]: entry for entry in context.plugin_manifest["plugins"]}
        configured = {
            stage["plugin"]
            for stage in context.pipeline["stages"]
            if entries.get(stage["plugin"], {}).get("role") == "evidence_adapter"
        }
        plan = {}
        issues = []
        for obligation_id, evidence_type in sorted(_required_slots(context)):
            raw = routes.get(evidence_type)
            if not isinstance(raw, dict):
                issues.append(f"{obligation_id}::{evidence_type}: route missing")
                continue
            mode = raw.get("mode")
            adapters = sorted(set(raw.get("adapters", [])))
            if mode not in {"any", "all"} or not adapters:
                issues.append(f"{obligation_id}::{evidence_type}: invalid route")
                continue
            unavailable = [
                adapter for adapter in adapters
                if adapter not in configured
                or entries.get(adapter, {}).get("implementation_status") != "executable"
            ]
            if unavailable:
                issues.append(
                    f"{obligation_id}::{evidence_type}: unavailable adapters {unavailable}"
                )
            plan.setdefault(obligation_id, {})[evidence_type] = {
                "mode": mode,
                "adapters": adapters,
            }
        if issues:
            return PluginResult(
                stage_id=context.stage_id,
                plugin_id=self.plugin_id,
                status=Status.FAIL,
                risk_level="CRITICAL",
                assurance=EvidenceAssurance.VERIFIED,
                findings=[Finding(
                    code="EVIDENCE_ROUTE_INCOMPLETE",
                    title="required_evidence_has_no_executable_route",
                    severity="P0",
                    detail=issue,
                ) for issue in issues],
                evidence_manifest={"route_plan": plan},
            )
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.PASS,
            risk_level="LOW",
            assurance=EvidenceAssurance.VERIFIED,
            evidence_manifest={"route_plan": plan},
        )


class WitnessAuditPlugin(Plugin):
    plugin_id = "witness.audit"
    layer = "L6"

    def run(self, context, config):
        target_types = {"construction_witness", "solver_falsification"}
        required_types = {evidence_type for _, evidence_type in _required_slots(context)}
        relevant = [
            closure
            for result in context.prior_results
            if result.status == Status.PASS and result.assurance == EvidenceAssurance.VERIFIED
            for closure in result.evidence_closures
            if closure.evidence_type in target_types
        ]
        if relevant:
            return PluginResult(
                stage_id=context.stage_id,
                plugin_id=self.plugin_id,
                status=Status.PASS,
                risk_level="LOW",
                assurance=EvidenceAssurance.VERIFIED,
                evidence_manifest={
                    "executed": [f"{item.obligation_id}::{item.evidence_type}" for item in relevant]
                },
            )
        if required_types.intersection(target_types):
            return _gate_failure(
                context,
                self.plugin_id,
                "WITNESS_OR_FALSIFICATION_NOT_EXECUTED",
                "A required witness or falsification slot has no verified evidence.",
                severity="P1",
            )
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.PASS,
            risk_level="LOW",
            assurance=EvidenceAssurance.VERIFIED,
            evidence_manifest={"applicable": False},
        )


class ReproductionAuditPlugin(Plugin):
    plugin_id = "reproduction.audit"
    layer = "L7"

    def run(self, context, config):
        closures = [
            closure
            for result in context.prior_results
            if result.status == Status.PASS and result.assurance == EvidenceAssurance.VERIFIED
            for closure in result.evidence_closures
        ]
        minimum = int(config.get("minimum_distinct_adapters", 2))
        if config.get("per_slot", False):
            selected_types = {
                str(value) for value in config.get("evidence_types", [])
            }
            required = {
                slot for slot in _required_slots(context)
                if not selected_types or slot[1] in selected_types
            }
            by_slot: dict[tuple[str, str], set[str]] = defaultdict(set)
            for closure in closures:
                by_slot[(closure.obligation_id, closure.evidence_type)].add(
                    closure.adapter_id
                )
            insufficient = {
                slot: sorted(by_slot.get(slot, set()))
                for slot in sorted(required)
                if len(by_slot.get(slot, set())) < minimum
            }
            if insufficient:
                detail = "; ".join(
                    f"{obligation}::{evidence_type} observed={adapters}"
                    for (obligation, evidence_type), adapters in insufficient.items()
                )
                return _gate_failure(
                    context,
                    self.plugin_id,
                    "INDEPENDENT_REPRODUCTION_PER_SLOT_INSUFFICIENT",
                    f"Required {minimum} adapters per selected evidence slot: {detail}",
                    severity="P1",
                )
            return PluginResult(
                stage_id=context.stage_id,
                plugin_id=self.plugin_id,
                status=Status.PASS,
                risk_level="LOW",
                assurance=EvidenceAssurance.VERIFIED,
                evidence_manifest={
                    "mode": "per_slot",
                    "minimum": minimum,
                    "slots": {
                        f"{obligation}::{evidence_type}": sorted(by_slot[(obligation, evidence_type)])
                        for obligation, evidence_type in sorted(required)
                    },
                },
            )
        adapters = {closure.adapter_id for closure in closures}
        if len(adapters) < minimum:
            return _gate_failure(
                context,
                self.plugin_id,
                "INDEPENDENT_REPRODUCTION_INSUFFICIENT",
                f"Required {minimum} evidence adapters, observed {len(adapters)}.",
                severity="P1",
            )
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.PASS,
            risk_level="LOW",
            assurance=EvidenceAssurance.VERIFIED,
            evidence_manifest={"distinct_adapters": sorted(adapters), "minimum": minimum},
        )


class GovernancePlugin(Plugin):
    plugin_id = "governance.final"
    layer = "L8"

    def run(self, context, config):
        verified = [
            result for result in context.prior_results
            if result.status == Status.PASS and result.assurance == EvidenceAssurance.VERIFIED
        ]
        verdicts = {result.claim_verdict for result in verified if result.claim_verdict}
        profile = derive_profile(context.prior_results)
        serialized_profile = serialize_profile(profile)
        if ClaimVerdict.SCOPE_MISMATCH in verdicts:
            return self._terminal(context, Verdict.SCOPE_MISMATCH, serialized_profile)
        if ClaimVerdict.REFUTED in verdicts:
            return self._terminal(context, Verdict.FAIL, serialized_profile)

        required_stage_ids = [
            stage["id"] for stage in context.pipeline["stages"]
            if stage.get("required") and stage["plugin"] != self.plugin_id
        ]
        by_stage = {result.stage_id: result for result in context.prior_results}
        unsatisfied_stages = [
            stage_id for stage_id in required_stage_ids
            if stage_id not in by_stage
            or by_stage[stage_id].status != Status.PASS
            or by_stage[stage_id].assurance != EvidenceAssurance.VERIFIED
        ]
        findings = [finding for result in context.prior_results for finding in result.findings]
        blocking_findings = [finding for finding in findings if finding.severity in {"P0", "P1"}]
        router = next((item for item in verified if item.plugin_id == "evidence.route"), None)
        route_plan = router.evidence_manifest.get("route_plan", {}) if router else {}
        closures: dict[tuple[str, str], set[str]] = defaultdict(set)
        rejected = []
        for result in verified:
            for closure in result.evidence_closures:
                policy = route_plan.get(closure.obligation_id, {}).get(closure.evidence_type, {})
                if closure.adapter_id in policy.get("adapters", []):
                    closures[(closure.obligation_id, closure.evidence_type)].add(closure.adapter_id)
                else:
                    rejected.append(
                        f"{closure.obligation_id}::{closure.evidence_type}::{closure.adapter_id}"
                    )
        closed = set()
        missing = []
        for obligation_id, evidence_type in sorted(_required_slots(context)):
            policy = route_plan.get(obligation_id, {}).get(evidence_type, {})
            allowed = set(policy.get("adapters", []))
            observed = closures.get((obligation_id, evidence_type), set())
            if policy.get("mode") == "all":
                absent = allowed - observed
                if allowed and not absent:
                    closed.add((obligation_id, evidence_type))
                else:
                    missing.extend(
                        f"{obligation_id}::{evidence_type}::{adapter}"
                        for adapter in sorted(absent or {"NO_ROUTE"})
                    )
            elif allowed.intersection(observed):
                closed.add((obligation_id, evidence_type))
            else:
                missing.append(f"{obligation_id}::{evidence_type}::ANY")
        assurance_failures = unmet_requirements(
            profile, context.pipeline.get("assurance_requirements", {})
        )
        if unsatisfied_stages or blocking_findings or missing or rejected or assurance_failures:
            evidence = (
                unsatisfied_stages
                + missing
                + rejected
                + assurance_failures
                + [finding.code for finding in blocking_findings]
            )
            return PluginResult(
                stage_id=context.stage_id,
                plugin_id=self.plugin_id,
                status=Status.FAIL,
                risk_level="CRITICAL",
                assurance=EvidenceAssurance.VERIFIED,
                decision=Verdict.REQUIRES_REVIEW,
                findings=[Finding(
                    code="GOVERNANCE_GATE_FAILED",
                    title="required_evidence_or_assurance_open",
                    severity="P0",
                    detail="A required gate, evidence slot, or assurance requirement is open.",
                    evidence=evidence,
                )],
                residual_risks=["The claim does not satisfy the strict false-acceptance policy."],
                evidence_manifest={
                    "decision": Verdict.REQUIRES_REVIEW.value,
                    "closed_slots": [f"{a}::{b}" for a, b in sorted(closed)],
                    "open_requirements": evidence,
                    "assurance_profile": serialized_profile,
                },
            )
        warnings = [finding for finding in findings if finding.severity in {"P2", "P3"}]
        if warnings:
            return PluginResult(
                stage_id=context.stage_id,
                plugin_id=self.plugin_id,
                status=Status.WARN,
                risk_level="MEDIUM",
                assurance=EvidenceAssurance.VERIFIED,
                decision=Verdict.REQUIRES_REVIEW,
                findings=[Finding(
                    code="GOVERNANCE_WARNINGS_OPEN",
                    title="noncritical_findings_require_review",
                    severity="P1",
                    detail="Evidence slots are closed, but warnings remain open.",
                    evidence=[finding.code for finding in warnings],
                )],
                evidence_manifest={"assurance_profile": serialized_profile},
            )
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.PASS,
            risk_level="LOW",
            assurance=EvidenceAssurance.VERIFIED,
            decision=Verdict.PASS,
            evidence_manifest={
                "decision": Verdict.PASS.value,
                "closed_slots": [f"{a}::{b}" for a, b in sorted(closed)],
                "assurance_profile": serialized_profile,
            },
        )

    def _terminal(self, context, decision, profile):
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.PASS,
            risk_level="CRITICAL",
            assurance=EvidenceAssurance.VERIFIED,
            decision=decision,
            evidence_manifest={"decision": decision.value, "assurance_profile": profile},
        )


def _gate_failure(context, plugin_id, code, detail, severity="P0"):
    return PluginResult(
        stage_id=context.stage_id,
        plugin_id=plugin_id,
        status=Status.FAIL,
        risk_level="CRITICAL",
        assurance=EvidenceAssurance.VERIFIED,
        findings=[Finding(
            code=code,
            title=code.lower(),
            severity=severity,
            detail=detail,
        )],
    )
