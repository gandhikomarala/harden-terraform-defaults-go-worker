# AGENTS.md — CloudGuard SAST Development & Operating Directives

## 1. Core Principles
- **Static Analysis Only**: Never execute uploaded Infrastructure-as-Code. Do not invoke `terraform apply` or deploy cloud infrastructure.
- **Explainable & Grounded Findings**: Do not fake security findings. Every rule must evaluate against real AST or normalized attributes.
- **Strict Secret Redaction**: Detect and mask AWS keys (`AKIA...`), RSA private keys, and passwords before logging or external API transport.
- **Deterministic Rules First**: Core security policies must run locally and offline without external AI dependencies.
- **Maintain Test Coverage**: Every rule must have accompanying unit test fixtures in `tests/fixtures/`.

## 2. Rule Development Protocol
1. Define Rule ID following format: `CG-<PROVIDER>-<SERVICE>-<NUM>` (e.g. `CG-AWS-S3-001`).
2. Map to authoritative compliance frameworks (CIS Cloud Benchmarks, NIST 800-53, OWASP).
3. Provide vulnerable and secure remediation fixtures.
4. Implement AST matcher in `app/core/rules/`.
5. Verify test pass with `pytest tests/`.
