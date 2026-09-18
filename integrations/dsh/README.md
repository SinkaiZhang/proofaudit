# DSH integration

This directory is an optional official bundle/patch-style DeepSeek Harness plugin. It exposes `proof_audit_run` and delegates to the installed standalone CLI:

```text
python -m proofaudit run --case ... --artifact-dir ...
```

The integration enforces allowed filesystem roots, cancellation, a hard subprocess timeout, and a 4 MiB capture limit. DSH is an orchestrator, not a mathematical trust root.

Install ProofAudit in the Python environment selected by `PROOFAUDIT_PYTHON`, then add this bundle to a DSH profile with the DSH plugin command.

