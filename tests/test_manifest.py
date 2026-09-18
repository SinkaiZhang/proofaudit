import json
from pathlib import Path

import pytest

from proofaudit.manifests import merge_manifests


def test_overlay_collision_fails(tmp_path: Path):
    plugin = tmp_path / "plugin.py"
    plugin.write_text("class Plugin: pass\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "interface_version": "0.1",
        "plugins": [{
            "id": "source.capture",
            "module_file": "plugin.py",
            "class": "Plugin",
            "layer": "L0",
            "role": "universal_gate",
            "implementation_status": "executable"
        }]
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="collision"):
        merge_manifests([manifest])

