# Reliability evaluation protocol

## Primary endpoint

The primary metric is false acceptance: the fraction of known-invalid cases receiving `PASS`. A sealed evaluation succeeds only with zero observed false acceptances. The report must include a one-sided confidence bound rather than claiming a true error rate of zero.

## Utility guardrail

At least 30 percent of valid or unmutated cases must receive `PASS`. Reliability and utility are separate constraints; one cannot compensate for the other.

## Benchmark tracks

- PDF-Lean main track: semantic fidelity when a formal certificate already exists.
- PDF-only exploratory track: risk localization, local formalization, and verified falsification.

Scores from the two tracks must not be merged into one correctness rate.

## Ground truth

- Controlled mutants use construction records and independent verifiers.
- Historical flaws use public corrections, counterexamples, or independent literature.
- Live claims retain adjudicated and unresolved states; they are not forced into binary labels.

Every defect family has a minimum 15 percent quota in the sealed set. Results report macro averages by family and cluster uncertainty by base case.

## Blind evaluation

An independent curator holds the sealed cases. The repository, pipeline, model prompts, and policy are frozen before a single official run. Test hashes are published before labels. Labels and cases are released after the blind evaluation.

## Baselines

- LLM-only
- Lean-only
- LLM plus Lean without ProofAudit gates
- Full ProofAudit

The model suite includes frontier closed models and at least one fixed open-weight model. Prompts, tool permissions, versions, repetitions, token usage, and cost are recorded.

