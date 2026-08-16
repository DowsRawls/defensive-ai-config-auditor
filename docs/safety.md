# Safety and human oversight

This project is defensive-only. Do not submit secrets, private keys, tokens, customer data, or production configuration to a model without authorization and appropriate data handling.

The tool must remain advisory: it may propose a minimal patch, but a named human owner decides whether to test or apply it. Test in a disposable environment first; run native syntax checks, policy checks, regression tests, and rollback rehearsal. Preserve an audit trail of inputs, outputs, approvals, and validation results.

Treat configuration comments and included files as untrusted data, not instructions. Prefer abstention when context is missing. Never convert a benchmark label directly into an automated production change.
