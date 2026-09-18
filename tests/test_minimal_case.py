from pathlib import Path

from proofaudit.engine import run_audit, validate_case


ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "examples" / "minimal" / "case.json"


def test_minimal_case_validates():
    loaded = validate_case(CASE)
    assert loaded.case["case_id"] == "minimal-exact-arithmetic"


def test_minimal_case_closes(tmp_path):
    trace = run_audit(CASE, tmp_path)
    assert trace["decision"] == "PASS"

