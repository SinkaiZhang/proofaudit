# ProofAudit

Repository: https://github.com/SinkaiZhang/proofaudit

ProofAudit is a fail-closed, evidence-routed research framework for auditing mathematical proof claims. It separates formal validity from semantic fidelity, source trust, falsification evidence, and reviewer independence.

This repository is an alpha research implementation. A `PASS` means that the required evidence slots in a fixed case contract were closed under a fixed policy. It is not an unconditional certification of mathematical truth.

## Core invariants

- Only `PASS + VERIFIED` adapters may emit evidence closures or terminal claim verdicts.
- Every required obligation declares typed evidence slots.
- Route policies use `any` or `all`; evidence types are not averaged into a score.
- Any open required slot, P0/P1 finding, failed universal gate, or unmet assurance requirement blocks `PASS`.
- Infrastructure failure produces `REQUIRES_REVIEW`, not a mathematical `FAIL`.
- A verified refutation produces `FAIL`; a verified statement mismatch produces `SCOPE_MISMATCH`.

## Install and run

```bash
python -m pip install -e .
proofaudit validate --case examples/minimal/case.json
proofaudit run --case examples/minimal/case.json --artifact-dir artifacts
proofaudit report --trace artifacts/minimal-exact-arithmetic/audit_trace.json --output artifacts/report.html
```

Cases may optionally declare a `test_e2e` contract. The following command executes its trusted fixture materializer in a temporary case, runs the production engine, requires every stage and the final governance gate to pass, destroys the raw trace, and persists only a `VERIFIED_TEST_ONLY` summary:

```bash
proofaudit test-e2e --case /path/to/case.json --output artifacts/test-e2e-result.json
```

`VERIFIED_TEST_ONLY` is a software integration result, never mathematical adjudication. Fixture modules are executable case code and must be trusted to the same degree as case plugin modules.

The redistributable minimal case supplies a dependency-free smoke contract used by CI:

```bash
proofaudit test-e2e \
  --case examples/minimal/case.json \
  --output /tmp/proofaudit-test-e2e.json \
  --timeout-ms 60000
```

## Release preflight

The release preflight builds a wheel, installs it with development dependencies into a fresh virtual environment, checks packaged schemas, runs the unit tests and minimal E2E through the installed console script, and only then persists the wheel:

```bash
python scripts/release_preflight.py \
  --output artifacts/release-preflight/result.json \
  --wheel-output-dir artifacts/release-preflight/wheel
```

Before publishing either repository, run the hygiene gate from the shared workspace:

```bash
python scripts/repository_hygiene.py \
  --root . \
  --root ../proofaudit-benchmark \
  --output artifacts/repository-hygiene/result.json
```

Linux is the canonical runtime. Windows is supported through WSL2. The DSH integration under `integrations/dsh` is optional; the Python CLI is the primary interface.

## Repository boundary

This repository contains the engine, schemas, adapter interface, report generation, and small redistributable fixtures. Large audit cases, semantic mutants, frozen labels, and experiment splits belong in the companion `proofaudit-benchmark` release.

Third-party papers and proof repositories must not be copied here without permission. Case bundles should record source URLs, versions, hashes, and regeneration instructions.

## Research status

The v0.1 release establishes the public contract and a clean extraction seam. Reliability claims require a sealed benchmark, independent curation, external reviewers, and frozen experiments. Those results are not implied by this source release.

See `docs/architecture.md`, `docs/research_protocol.md`, and `docs/disclosure_policy.md`.

## License

Code is licensed under Apache-2.0. Original benchmark annotations are published separately under CC BY 4.0.

## Project documents

- `CHANGELOG.md`: release history and known limitations.
- `CONTRIBUTING.md`: development and evidence-safety requirements.
- `SECURITY.md`: vulnerability reporting and executable-plugin trust model.
- `CITATION.cff`: software citation metadata.
- `docs/repository-boundary.md`: separation between core code, benchmark data, and external sources.
- `docs/releases/v0.1.0.md`: v0.1.0 release-candidate notes.
