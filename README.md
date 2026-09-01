# CloudGuard SAST — Infrastructure-as-Code Security & Compliance Scanner

CloudGuard SAST is an enterprise-grade web-based static application security testing (SAST) platform for Infrastructure-as-Code (IaC). It analyzes Terraform, AWS CloudFormation, and YAML configurations against CIS Benchmarks, NIST 800-53, and OWASP security standards.

## Architecture
- **Interactive Code Studio**: High-performance editor with syntax highlighting, sample preloading, and line-level vulnerability markers.
- **Parser & Normalization Layer**: Converts Terraform HCL, CloudFormation templates, and YAML into a unified `NormalizedResource` model.
- **Deterministic Rule Engine**: AST-based evaluation for S3 public access, unrestricted SSH ingress, unencrypted RDS databases, and exposed database ports.
- **Remediation Diff Generator**: Generates clean unified diffs (`--- insecure +++ secure`) and one-click editor patch application.
- **Secret Redaction Engine**: Automated pattern matching for credentials, API tokens, and private keys.

## Quick Start
```bash
# Backend Setup
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Docker Deployment
docker-compose up -d --build
```
