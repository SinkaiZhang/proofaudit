from __future__ import annotations

import json
import zipfile
from pathlib import Path

from .engine import validate_case
from .io import load_data, resolve_within, sha256_bytes


def pack_case(case_path: str | Path, output_path: str | Path) -> Path:
    loaded = validate_case(case_path)
    paths = {
        loaded.case_path,
        resolve_within(loaded.root, loaded.case["claim"]),
        resolve_within(loaded.root, loaded.case["pipeline"]),
        resolve_within(loaded.root, loaded.case["source_lock"]),
        *loaded.overlay_manifests,
    }
    bridge = resolve_within(loaded.root, loaded.claim["semantic_bridge"]["path"])
    paths.add(bridge)
    for manifest_path in loaded.overlay_manifests:
        manifest = load_data(manifest_path)
        for entry in manifest["plugins"]:
            if "module_file" in entry:
                paths.add(resolve_within(manifest_path.parent, entry["module_file"]))
    for source in loaded.source_lock["sources"]:
        if source.get("redistributable", False):
            paths.add(resolve_within(loaded.root, source["path"]))
    records = []
    for path in sorted(paths):
        relative = path.relative_to(loaded.root).as_posix()
        payload = path.read_bytes()
        records.append((relative, payload, sha256_bytes(payload)))
    manifest_payload = json.dumps(
        {
            "schema_version": "0.1",
            "case_id": loaded.case["case_id"],
            "files": [{"path": name, "sha256": digest} for name, _, digest in records],
        },
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    output = Path(output_path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload, _ in records + [("PACK_MANIFEST.json", manifest_payload, "")]:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            archive.writestr(info, payload)
    return output

