"""Public ProofAudit interface."""

from .engine import run_audit, validate_case
from .models import (
    ArtifactRef,
    AssuranceDimension,
    AssuranceLevel,
    EvidenceClosure,
    Finding,
    Plugin,
    PluginResult,
    Verdict,
)

__all__ = [
    "ArtifactRef",
    "AssuranceDimension",
    "AssuranceLevel",
    "EvidenceClosure",
    "Finding",
    "Plugin",
    "PluginResult",
    "Verdict",
    "run_audit",
    "validate_case",
]

__version__ = "0.1.0"

