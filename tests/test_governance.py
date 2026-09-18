from proofaudit.assurance import unmet_requirements
from proofaudit.models import AssuranceDimension, AssuranceLevel, DimensionAssessment


def test_assurance_dimensions_do_not_average():
    profile = {
        dimension: DimensionAssessment(AssuranceLevel.UNASSESSED)
        for dimension in AssuranceDimension
    }
    profile[AssuranceDimension.FORMAL] = DimensionAssessment(AssuranceLevel.INDEPENDENT)
    failures = unmet_requirements(profile, {"semantic": "VERIFIED"})
    assert failures == ["semantic: required VERIFIED, observed UNASSESSED"]

