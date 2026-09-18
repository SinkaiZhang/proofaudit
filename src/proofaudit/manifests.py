from __future__ import annotations

import hashlib
import importlib.util
import sys
from importlib import import_module
from pathlib import Path
from typing import Any, Iterable

from .io import load_data, resolve_within, sha256_file
from .validation import validate_document


DEFAULT_MANIFEST = Path(__file__).resolve().parent / "default_manifest.json"


def load_manifest(path: Path) -> dict[str, Any]:
    path = path.resolve()
    payload = load_data(path)
    validate_document(payload, "plugin-manifest.v0.1.schema.json")
    entries = []
    for raw in payload["plugins"]:
        entry = dict(raw)
        if "module_file" in entry:
            entry["_module_file"] = str(resolve_within(path.parent, entry["module_file"]))
        entries.append(entry)
    payload["plugins"] = entries
    payload["_manifest_path"] = str(path)
    payload["_manifest_sha256"] = sha256_file(path)
    return payload


def merge_manifests(overlays: Iterable[Path] = ()) -> dict[str, Any]:
    manifests = [load_manifest(DEFAULT_MANIFEST)]
    manifests.extend(load_manifest(path) for path in overlays)
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for manifest in manifests:
        for entry in manifest["plugins"]:
            plugin_id = entry["id"]
            if plugin_id in seen:
                raise ValueError(f"plugin ID collision: {plugin_id}")
            seen.add(plugin_id)
            entries.append(entry)
    return {
        "interface_version": "0.1",
        "plugins": entries,
        "manifest_sources": [
            {
                "uri": Path(item["_manifest_path"]).name,
                "sha256": item["_manifest_sha256"],
            }
            for item in manifests
        ],
    }


def load_plugins(manifest: dict[str, Any]) -> dict[str, type]:
    loaded: dict[str, type] = {}
    for entry in manifest["plugins"]:
        if "module" in entry:
            module = import_module(entry["module"])
        else:
            module_path = Path(entry["_module_file"])
            module_name = "_proofaudit_case_" + hashlib.sha256(
                f"{entry['id']}:{module_path}".encode("utf-8")
            ).hexdigest()
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            if spec is None or spec.loader is None:
                raise ValueError(f"cannot load plugin module: {module_path}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        plugin_class = getattr(module, entry["class"], None)
        if plugin_class is None:
            raise ValueError(f"plugin class not found: {entry['id']}::{entry['class']}")
        loaded[entry["id"]] = plugin_class
    return loaded

