from __future__ import annotations

import html
import json
from pathlib import Path

from .io import load_data


def render_report(trace_path: str | Path, output_path: str | Path) -> Path:
    trace = load_data(Path(trace_path).expanduser().resolve())
    stages = []
    for stage in trace.get("stages", []):
        findings = "".join(
            "<li><strong>{}</strong>: {}</li>".format(
                html.escape(item.get("code", "")), html.escape(item.get("detail", ""))
            )
            for item in stage.get("findings", [])
        ) or "<li>None</li>"
        stages.append(
            "<section><h2>{}</h2><p>{} / {} / {}</p><ul>{}</ul></section>".format(
                html.escape(stage.get("stage_id", "")),
                html.escape(stage.get("plugin_id", "")),
                html.escape(stage.get("status", "")),
                html.escape(stage.get("assurance", "")),
                findings,
            )
        )
    profile = html.escape(json.dumps(trace.get("assurance_profile", {}), indent=2))
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>ProofAudit report</title><style>
body{{font-family:Georgia,serif;max-width:980px;margin:3rem auto;padding:0 1.2rem;color:#18211d;background:#f4f0e6}}
header,section{{background:#fffdf7;border:1px solid #c8c1ad;padding:1.2rem;margin:1rem 0}}
h1,h2{{font-family:"Trebuchet MS",sans-serif}} pre{{overflow:auto;background:#18211d;color:#eef5ee;padding:1rem}}
</style></head><body><header><h1>{html.escape(trace.get('case_id',''))}</h1>
<p>Decision: <strong>{html.escape(trace.get('decision',''))}</strong></p></header>
<section><h2>Assurance profile</h2><pre>{profile}</pre></section>{''.join(stages)}</body></html>"""
    output = Path(output_path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")
    return output

