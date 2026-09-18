from __future__ import annotations

from .models import (
    ASSURANCE_ORDER,
    AssuranceDimension,
    AssuranceLevel,
    DimensionAssessment,
    EvidenceAssurance,
    PluginResult,
    Status,
    serialize,
)


def empty_profile() -> dict[AssuranceDimension, DimensionAssessment]:
    return {
        dimension: DimensionAssessment(level=AssuranceLevel.UNASSESSED)
        for dimension in AssuranceDimension
    }


def derive_profile(results: list[PluginResult]) -> dict[AssuranceDimension, DimensionAssessment]:
    profile = empty_profile()
    for result in results:
        if result.status != Status.PASS or result.assurance != EvidenceAssurance.VERIFIED:
            continue
        for dimension, candidate in result.assurance_contributions.items():
            current = profile[dimension]
            if ASSURANCE_ORDER[candidate.level] > ASSURANCE_ORDER[current.level]:
                profile[dimension] = candidate
            elif candidate.level == current.level and candidate.level != AssuranceLevel.UNASSESSED:
                profile[dimension] = DimensionAssessment(
                    level=current.level,
                    evidence=tuple(sorted(set(current.evidence + candidate.evidence))),
                    shared_dependencies=tuple(
                        sorted(set(current.shared_dependencies + candidate.shared_dependencies))
                    ),
                    residual_risks=tuple(
                        sorted(set(current.residual_risks + candidate.residual_risks))
                    ),
                )
    return profile


def unmet_requirements(
    profile: dict[AssuranceDimension, DimensionAssessment],
    raw_requirements: dict[str, str],
) -> list[str]:
    failures = []
    for raw_dimension, raw_level in raw_requirements.items():
        dimension = AssuranceDimension(raw_dimension)
        required = AssuranceLevel(raw_level)
        observed = profile[dimension].level
        if ASSURANCE_ORDER[observed] < ASSURANCE_ORDER[required]:
            failures.append(f"{dimension.value}: required {required.value}, observed {observed.value}")
    return failures


def serialize_profile(
    profile: dict[AssuranceDimension, DimensionAssessment],
) -> dict[str, object]:
    return {dimension.value: serialize(assessment) for dimension, assessment in profile.items()}

