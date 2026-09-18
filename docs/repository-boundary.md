# Repository boundary

ProofAudit is released as two coordinated repositories plus externally referenced source material.

## `proofaudit`

The core software repository contains:

- the audit engine and public Python interface;
- JSON schemas and verdict semantics;
- default adapters, report generation, and DSH integration;
- small redistributable fixtures;
- unit tests, CI, packaging, and release automation.

It must not contain benchmark ground truth, sealed test cases, or third-party papers and proof repositories without redistribution permission.

## `proofaudit-benchmark`

The companion data repository contains:

- case contracts and source locks;
- original alignment annotations and obligation graphs;
- defect taxonomy, labels, splits, and sealed-set commitments;
- case-specific executable adapters and review interfaces;
- regeneration instructions for evidence derived from external sources.

Synthetic `TEST_ONLY` outputs test software integration and must never become benchmark labels or expert evidence.

## External material

Third-party PDFs, Lean repositories, model outputs, solvers, and toolchains remain outside both repositories unless their licenses permit redistribution. A source lock records identity and provenance but does not grant rights or establish safety.

## Compatibility

Core releases use semantic package versions. Benchmark releases declare a compatible core series and retain their own dataset version. A benchmark case is reproducible only when its case schema, core version, source hashes, plugin code, and external tool pins are all fixed.
