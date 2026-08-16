# Methodology

## Purpose

The benchmark measures review quality on small, synthetic configuration excerpts. It is a pipeline MVP, not evidence of production readiness.

## Protocol

1. Freeze a benchmark version and record model, prompt, parameters, and date.
2. Give the reviewer only the case description and `config`; keep labels hidden.
3. Require structured finding IDs, rationale, proposed remediation, confidence, and an abstain/escalate option.
4. Score finding IDs with the bundled evaluator.
5. Have a qualified human review every remediation.
6. Where feasible, apply proposed changes only in an isolated disposable environment and run syntax, policy, and functional checks.
7. Report all cases, failures, exclusions, and uncertainty. Do not tune on the held-out evaluation set.

## Metrics

Report finding-level TP, FP, FN, precision, and recall. Report case-level false-positive rate as the share of neutral control cases receiving any finding. Also report the fraction of assessed remediations that pass review and isolated validation, plus coverage: how many remediations were actually assessed. A remediation is valid only if it addresses the labeled issue, introduces no known regression, passes syntax checks, and preserves declared functionality.

## Dataset growth

Future versions should separate development and held-out sets, add paired format variants, use multiple independent labelers, document disagreements, and stratify results by domain and severity. Confidence intervals are appropriate once sample sizes support them.
