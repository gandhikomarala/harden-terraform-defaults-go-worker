# PROJECT_STATUS.md — CloudGuard SAST

## Current Milestone: Milestone 15 — Full Platform Release & TrainPlex Production
- **Platform Name**: CloudGuard SAST
- **Supported Formats**: Terraform (`.tf`), AWS CloudFormation (`.yaml`, `.json`), Generic YAML/JSON
- **Security Rule Engine**: 7 Core Deterministic Rules with AST Matching
- **Compliance Mappings**: CIS AWS Foundations Benchmark v3.0, NIST 800-53 Rev 5, OWASP Top 10
- **Remediation Engine**: Unified Diff & Side-by-Side Patch Generator with "Apply to Editor"
- **Test Status**: 100% Passing (FastAPI endpoints, parsers, rules, secret redaction)
- **CI/CD Status**: GitHub Actions multi-job pipeline active
