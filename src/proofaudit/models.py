from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Status(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


class EvidenceAssurance(StrEnum):
    VERIFIED = "VERIFIED"
    ASSERTED = "ASSERTED"
    UNVERIFIED = "UNVERIFIED"


class Verdict(StrEnum):
    PASS = "PASS"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    FAIL = "FAIL"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"


class ClaimVerdict(StrEnum):
    REFUTED = "REFUTED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"


class AssuranceDimension(StrEnum):
    FORMAL = "formal"
    SEMANTIC = "semantic"
    SOURCE = "source"
    FALSIFICATION = "falsification"
    HUMAN_INDEPENDENCE = "human_independence"


class AssuranceLevel(StrEnum):
    UNASSESSED = "UNASSESSED"
    ASSERTED = "ASSERTED"
    VERIFIED = "VERIFIED"
    INDEPENDENT = "INDEPENDENT"


ASSURANCE_ORDER = {
    AssuranceLevel.UNASSESSED: 0,
    AssuranceLevel.ASSERTED: 1,
    AssuranceLevel.VERIFIED: 2,
    AssuranceLevel.INDEPENDENT: 3,
}


@dataclass(frozen=True)
class ArtifactRef:
    uri: str
    sha256: str
    generated_by: str
    media_type: str = "application/json"


@dataclass(frozen=True)
class EvidenceClosure:
    obligation_id: str
    evidence_type: str
    adapter_id: str
    artifact: ArtifactRef
    verification_method: str
    trusted_dependencies: tuple[str, ...] = ()
    shared_dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class DimensionAssessment:
    level: AssuranceLevel
    evidence: tuple[str, ...] = ()
    shared_dependencies: tuple[str, ...] = ()
    residual_risks: tuple[str, ...] = ()


@dataclass
class Finding:
    code: str
    title: str
    severity: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    reproducible_command: str | None = None


@dataclass
class PluginResult:
    stage_id: str
    plugin_id: str
    status: Status
    risk_level: str
    assurance: EvidenceAssurance = EvidenceAssurance.UNVERIFIED
    evidence_closures: list[EvidenceClosure] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, ArtifactRef | str] = field(default_factory=dict)
    trusted_dependencies: list[str] = field(default_factory=list)
    residual_risks: list[str] = field(default_factory=list)
    reproduction_commands: list[str] = field(default_factory=list)
    evidence_manifest: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    assurance_contributions: dict[AssuranceDimension, DimensionAssessment] = field(
        default_factory=dict
    )
    runtime_ms: int | None = None
    claim_verdict: ClaimVerdict | None = None
    decision: Verdict | None = None


@dataclass(frozen=True)
class ClaimBundle:
    claim_id: str
    title: str
    statement: str
    domain: str
    assumptions: tuple[str, ...]
    conclusion_type: str
    sources: tuple[str, ...]
    semantic_bridge: dict[str, Any]
    obligation_graph: dict[str, Any]
    dependencies: tuple[dict[str, Any], ...]
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ClaimBundle":
        return cls(
            claim_id=str(data["claim_id"]),
            title=str(data["title"]),
            statement=str(data["statement"]),
            domain=str(data["domain"]),
            assumptions=tuple(str(value) for value in data.get("assumptions", [])),
            conclusion_type=str(data["conclusion_type"]),
            sources=tuple(str(value) for value in data.get("sources", [])),
            semantic_bridge=dict(data["semantic_bridge"]),
            obligation_graph=dict(data["obligation_graph"]),
            dependencies=tuple(dict(value) for value in data.get("dependencies", [])),
            raw=data,
        )


@dataclass
class StageContext:
    stage_id: str
    claim: ClaimBundle
    case: dict[str, Any]
    pipeline: dict[str, Any]
    plugin_manifest: dict[str, Any]
    source_lock: dict[str, Any]
    prior_results: list[PluginResult]
    case_root: Path
    artifact_dir: Path


class Plugin:
    plugin_id = "base"
    layer = "base"

    def run(self, context: StageContext, config: dict[str, Any]) -> PluginResult:
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.SKIP,
            risk_level="LOW",
        )


def serialize(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return serialize(asdict(value))
    if isinstance(value, dict):
        return {str(serialize(key)): serialize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [serialize(item) for item in value]
    if isinstance(value, Path):
        return value.as_posix()
    return value


def failure(
    stage_id: str,
    plugin_id: str,
    code: str,
    title: str,
    detail: str,
    *,
    severity: str = "P0",
) -> PluginResult:
    return PluginResult(
        stage_id=stage_id,
        plugin_id=plugin_id,
        status=Status.FAIL,
        risk_level="CRITICAL",
        assurance=EvidenceAssurance.VERIFIED,
        findings=[Finding(code=code, title=title, severity=severity, detail=detail)],
    )

