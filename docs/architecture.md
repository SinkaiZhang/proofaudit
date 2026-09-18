# ProofAudit v0.1 architecture

## Trust model

ProofAudit audits a fixed claim contract. It does not ask a language model for a single correctness score. The engine routes every required obligation to typed evidence adapters and accepts closures only from adapters that return `PASS + VERIFIED` in the current run.

The universal flow is:

```text
source lock -> claim -> semantic bridge -> obligation DAG -> dependency trust
            -> evidence routing -> adapters -> witness/falsification
            -> reproduction -> fail-closed governance
```

## Stable seam

An evidence adapter receives a `StageContext` and returns a `PluginResult`. A valid closure identifies one obligation, one evidence type, the executing adapter, a content-addressed artifact, a verification method, and shared trust dependencies.

The engine rejects closures that refer to unknown obligations, undeclared evidence types, another adapter, malformed hashes, or unverified results.

## Assurance profile

The verdict and assurance profile are separate outputs. The five dimensions are:

- Formal
- Semantic
- Source
- Falsification
- Human Independence

Each dimension is `UNASSESSED`, `ASSERTED`, `VERIFIED`, or `INDEPENDENT`. Dimensions are never averaged. A pipeline can require minimum levels independently.

## Verdict semantics

- `PASS`: all required gates, slots, and assurance requirements are closed.
- `REQUIRES_REVIEW`: evidence, infrastructure, semantics, or policy remains open.
- `FAIL`: a verified adapter refuted the authoritative claim.
- `SCOPE_MISMATCH`: a verified adapter established that the audited formal statement is not the authoritative claim.

The governance safety property is structural: if the engine contract is enforced, an open required slot cannot produce `PASS`. It does not prove that an adapter, source, or reviewer is infallible.

## Source assurance

Source locks distinguish actual `source_payload` files from `reference_metadata`. A matching payload hash contributes `source: VERIFIED`. A matching metadata record proves only that a URL, revision, or expected hash was recorded without alteration, so it contributes at most `source: ASSERTED`. Fetching and checking the referenced external payload requires a dedicated adapter or a later source-capture run.

Dependency trust is also two-phase. The pre-adapter `pinning` gate rejects floating dependency identifiers. The post-adapter `attestation` gate accepts a dependency only when its claim record is already verified or a `PASS + VERIFIED` adapter in the current run names that dependency in `trusted_dependencies`.
