from __future__ import annotations

import json
import shutil
from pathlib import Path


def materialize(
    *,
    source_case_root: Path,
    target_case_root: Path,
    ephemeral_root: Path,
) -> dict:
    shutil.copytree(
        source_case_root,
        target_case_root,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    marker = {
        "schema_version": "test_only_fixture.v1",
        "non_adjudicative": True,
        "fixture": "minimal-exact-arithmetic",
        "ephemeral_root_owned_by_core": str(ephemeral_root) != "",
    }
    (target_case_root / "TEST_ONLY_NON_ADJUDICATIVE.json").write_text(
        json.dumps(marker, indent=2) + "\n",
        encoding="utf-8",
    )
    return {"fixture": marker["fixture"]}
