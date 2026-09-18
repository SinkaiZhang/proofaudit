# Security policy

## Supported versions

The project is pre-1.0. Security fixes target the current `0.1.x` line only.

## Reporting a vulnerability

Use the hosting repository's private "Report a vulnerability" function. If that function is unavailable, open a public issue requesting a private contact channel without including exploit details, credentials, embargoed source material, or unpublished mathematical evidence.

## Trust model

ProofAudit validates paths and evidence contracts, but it is not a sandbox. Case plugin modules and `test_e2e` materializers execute Python code with the permissions of the invoking user. Run only trusted case bundles, preferably inside an isolated operating-system account or container.

External Lean repositories, build tools, solvers, PDFs, and reviewer signatures remain separate trust dependencies. Hash pinning establishes identity, not safety.

## Mathematical findings

A suspected mathematical error is normally a research finding, not a software vulnerability. Treat it as a security issue only when the system can be made to accept malformed, untrusted, or forged evidence contrary to its declared policy.
