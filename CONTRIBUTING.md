# Contributing to ProofAudit

## Scope

The core repository accepts changes to the engine, schemas, default adapters, CLI, reports, documentation, integrations, and small redistributable fixtures. Large mathematical cases, labels, semantic mutants, and experiment splits belong in `proofaudit-benchmark`.

## Development setup

```bash
python -m pip install -e ".[dev]"
pytest
proofaudit test-e2e \
  --case examples/minimal/case.json \
  --output /tmp/proofaudit-test-e2e.json \
  --timeout-ms 60000
```

Before proposing a release, run:

```bash
python scripts/release_preflight.py \
  --output artifacts/release-preflight/result.json
```

## Design requirements

- Preserve fail-closed behavior. Missing or malformed evidence must not become `PASS`.
- Keep formal validity, semantic fidelity, source trust, falsification, and reviewer independence separate.
- Require `PASS + VERIFIED` before an adapter emits an evidence closure or terminal claim verdict.
- Keep artifact paths portable and confined to the case root.
- Treat plugin modules and test materializers as trusted executable code.
- Mark all synthetic integration outputs `TEST_ONLY` and non-adjudicative.
- Do not add third-party papers, repositories, or model outputs without redistribution permission.

## Change checklist

- Explain the failure mode or research requirement addressed by the change.
- Update schemas and documentation when an interface changes.
- Add or update a minimal fixture for new behavior.
- Run unit tests and the minimal isolated E2E.
- Report any compatibility impact on `proofaudit-benchmark`.

Contributions are submitted under the repository's Apache-2.0 license unless explicitly marked otherwise.
