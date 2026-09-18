from __future__ import annotations

import json

from proofaudit import (
    ArtifactRef,
    AssuranceDimension,
    AssuranceLevel,
    EvidenceClosure,
    Plugin,
    PluginResult,
)
from proofaudit.io import sha256_file
from proofaudit.models import DimensionAssessment, EvidenceAssurance, Status


class ExactArithmeticPlugin(Plugin):
    plugin_id = "fixture.exact-arithmetic"
    layer = "L5"

    def run(self, context, config):
        observed = 2 + 2
        passed = observed == 4
        payload = {"expression": "2 + 2", "observed": observed, "expected": 4, "passed": passed}
        path = context.artifact_dir / "exact_arithmetic.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        artifact = ArtifactRef(
            uri="exact_arithmetic.json",
            sha256=sha256_file(path),
            generated_by=self.plugin_id,
        )
        if not passed:
            raise AssertionError("exact arithmetic witness failed")
        return PluginResult(
            stage_id=context.stage_id,
            plugin_id=self.plugin_id,
            status=Status.PASS,
            risk_level="LOW",
            assurance=EvidenceAssurance.VERIFIED,
            evidence_closures=[EvidenceClosure(
                obligation_id="fixture.two-plus-two",
                evidence_type="construction_witness",
                adapter_id=self.plugin_id,
                artifact=artifact,
                verification_method="Direct exact integer evaluation with a serialized result.",
                trusted_dependencies=("python-integer-semantics",),
            )],
            artifacts={"result": artifact},
            assurance_contributions={
                AssuranceDimension.FALSIFICATION: DimensionAssessment(
                    level=AssuranceLevel.VERIFIED,
                    evidence=(artifact.uri,),
                    shared_dependencies=("python-runtime",),
                )
            },
        )

