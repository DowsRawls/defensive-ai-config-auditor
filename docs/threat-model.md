# Threat model

## Protected assets

Service availability, configuration confidentiality, host boundaries, least privilege, auditability, and the integrity of human decisions.

## In scope

- Accidental or inherited Docker, Nginx, and Linux service misconfiguration.
- False negatives, false positives, hallucinated directives, over-broad patches, and functionality regressions.
- Prompt injection or untrusted text embedded in configuration comments.
- Excessive automation and insufficient human oversight.

## Out of scope

Target discovery, credential theft, exploit development, persistence, evasion, or instructions for attacking real systems. The benchmark does not prove a system safe for autonomous production changes.

## Trust boundaries

Configuration input is untrusted. Model output is untrusted. The evaluator computes label metrics but cannot establish operational safety. A human approver and an isolated validation environment are separate controls.
