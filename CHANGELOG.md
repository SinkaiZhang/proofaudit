# Changelog

All notable changes to ProofAudit are documented here.

## Unreleased

## [0.1.0] - 2026-09-18

- Added a fail-closed audit engine with four-state claim decisions.
- Added typed obligation graphs, evidence routing, assurance profiles, and governance gates.
- Added source, semantic, dependency, witness, reproduction, Lean replay, and Comparator adapters.
- Added portable case, claim, pipeline, source-lock, plugin-manifest, and test-E2E schemas.
- Added `validate`, `run`, `report`, `pack`, `migrate-legacy`, and `test-e2e` CLI commands.
- Added isolated `VERIFIED_TEST_ONLY` integration testing that cannot serve as adjudication evidence.
- Added a redistributable exact-arithmetic smoke case and GitHub Actions CI.
- Added wheel clean-install and release-preflight automation.

### Known limitations

- The project remains an alpha research implementation.
- A pipeline `PASS` is relative to a fixed case contract and policy, not unconditional mathematical truth.
- Case plugins and test materializers are trusted executable code, not a security sandbox.
- Large audit cases and benchmark labels are released separately.
