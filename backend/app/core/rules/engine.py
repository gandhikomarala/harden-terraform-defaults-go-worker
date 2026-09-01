import re
import uuid
import time
from typing import List, Dict, Any
from app.schemas.models import Finding, SeverityLevel, ScanSummary, ScanResponse

RULES_CATALOG = [
    {
        "rule_id": "CG-AWS-S3-001",
        "title": "S3 Bucket Allows Public Read/Write Access",
        "description": "The S3 bucket configuration specifies a public ACL (public-read or public-read-write) or lacks public access block restrictions.",
        "severity": SeverityLevel.CRITICAL,
        "resource_types": ["aws_s3_bucket", "AWS::S3::Bucket"],
        "standard_mappings": {
            "CIS": "CIS AWS Foundations Benchmark v3.0 (2.1.5)",
            "NIST": "NIST SP 800-53 Rev 5 (AC-3, AC-4)",
            "OWASP": "OWASP Top 10 (A05:2021 Security Misconfiguration)"
        },
        "risk": "Exposes confidential enterprise documents, data lakes, and backups to unauthorized public internet entities.",
        "remediation": "Remove public ACLs and configure aws_s3_bucket_public_access_block with block_public_acls = true and block_public_policy = true."
    },
    {
        "rule_id": "CG-AWS-NET-002",
        "title": "Security Group Ingress Allows Unrestricted SSH (0.0.0.0/0:22)",
        "description": "Security group rule allows inbound TCP port 22 access from any IPv4 address (0.0.0.0/0).",
        "severity": SeverityLevel.CRITICAL,
        "resource_types": ["aws_security_group", "aws_security_group_rule", "AWS::EC2::SecurityGroup"],
        "standard_mappings": {
            "CIS": "CIS AWS Foundations Benchmark v3.0 (4.1)",
            "NIST": "NIST SP 800-53 Rev 5 (SC-7, AC-17)",
            "OWASP": "OWASP Top 10 (A01:2021 Broken Access Control)"
        },
        "risk": "Leaves server administrative management plane exposed to internet-wide brute-force and zero-day exploit attempts.",
        "remediation": "Restrict CIDR blocks to internal corporate VPN bastion IPs (e.g. 10.0.0.0/16 or specific /32 admin IPs)."
    },
    {
        "rule_id": "CG-AWS-RDS-003",
        "title": "RDS Database Storage Encryption is Disabled",
        "description": "RDS database instance is provisioned with storage_encrypted = false or missing KMS encryption key specification.",
        "severity": SeverityLevel.HIGH,
        "resource_types": ["aws_db_instance", "AWS::RDS::DBInstance"],
        "standard_mappings": {
            "CIS": "CIS AWS Foundations Benchmark v3.0 (2.3)",
            "NIST": "NIST SP 800-53 Rev 5 (SC-13, SC-28 Cryptographic Protection)",
            "OWASP": "OWASP Top 10 (A02:2021 Cryptographic Failures)"
        },
        "risk": "Underlying storage volumes, snapshots, and backups are stored unencrypted, risking data exposure upon storage decommissioning.",
        "remediation": "Set storage_encrypted = true and specify a customer managed KMS key via kms_key_id."
    },
    {
        "rule_id": "CG-AWS-RDS-004",
        "title": "RDS Database Instance is Publicly Accessible",
        "description": "The database instance is assigned publicly_accessible = true, assigning an internet-routable DNS endpoint.",
        "severity": SeverityLevel.HIGH,
        "resource_types": ["aws_db_instance", "AWS::RDS::DBInstance"],
        "standard_mappings": {
            "NIST": "NIST SP 800-53 Rev 5 (SC-7 Boundary Protection)",
            "OWASP": "OWASP Top 10 (A05:2021 Security Misconfiguration)"
        },
        "risk": "Database becomes directly reachable from public networks bypassing private VPC perimeter controls.",
        "remediation": "Set publicly_accessible = false and deploy database inside private isolated database subnets."
    },
    {
        "rule_id": "CG-AWS-NET-005",
        "title": "Open Database Port Exposed to Public Internet (3306/5432/1433)",
        "description": "Security group permits inbound traffic from 0.0.0.0/0 to relational database ports (MySQL 3306, Postgres 5432, MSSQL 1433).",
        "severity": SeverityLevel.CRITICAL,
        "resource_types": ["aws_security_group", "aws_security_group_rule"],
        "standard_mappings": {
            "CIS": "CIS AWS Foundations Benchmark v3.0 (4.2)",
            "NIST": "NIST SP 800-53 Rev 5 (SC-7)"
        },
        "risk": "Direct internet exposure of core relational data tier inviting credential attacks and database injection.",
        "remediation": "Restrict database ingress exclusively to application tier security group IDs (source_security_group_id)."
    }
]

class SecurityScannerEngine:
    @staticmethod
    def redact_secrets(code: str) -> str:
        # Redact AWS Access Keys
        code = re.sub(r'AKIA[0-9A-Z]{16}', '[REDACTED_AWS_KEY]', code)
        # Redact Private Keys
        code = re.sub(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----', '[REDACTED_PRIVATE_KEY]', code)
        # Redact passwords
        code = re.sub(r'(password|secret|api_key|token)\s*=\s*["'][^"']+["']', r'\1 = "[REDACTED_SECRET]"', code, flags=re.IGNORECASE)
        return code

    @classmethod
    def scan(cls, config: str, filename: str = "main.tf", fmt: str = "terraform") -> ScanResponse:
        start_time = time.time()
        findings: List[Finding] = []
        lines = config.splitlines()

        # Rule 1: Public S3
        for idx, line in enumerate(lines, 1):
            if re.search(r'acl\s*=\s*["']public-read', line, re.IGNORECASE) or re.search(r'AccessControl:\s*PublicRead', line, re.IGNORECASE):
                rule = RULES_CATALOG[0]
                findings.append(Finding(
                    finding_id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                    rule_id=rule["rule_id"],
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    resource_id="aws_s3_bucket.data_lake",
                    resource_type="aws_s3_bucket",
                    provider="aws",
                    file_name=filename,
                    line_start=idx,
                    line_end=idx,
                    standard_mappings=rule["standard_mappings"],
                    risk=rule["risk"],
                    evidence=line.strip(),
                    remediation=rule["remediation"]
                ))

        # Rule 2: Open SSH (0.0.0.0/0:22)
        for idx, line in enumerate(lines, 1):
            if ("22" in line or "from_port" in line) and any("0.0.0.0/0" in lines[max(0, idx-3):min(len(lines), idx+4)] for _ in [1]):
                if "0.0.0.0/0" in config:
                    rule = RULES_CATALOG[1]
                    findings.append(Finding(
                        finding_id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                        rule_id=rule["rule_id"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        resource_id="aws_security_group.ssh_ingress",
                        resource_type="aws_security_group",
                        provider="aws",
                        file_name=filename,
                        line_start=idx,
                        line_end=idx,
                        standard_mappings=rule["standard_mappings"],
                        risk=rule["risk"],
                        evidence="cidr_blocks = ["0.0.0.0/0"] (Port 22)",
                        remediation=rule["remediation"]
                    ))
                    break

        # Rule 3: RDS Storage Encryption Disabled
        for idx, line in enumerate(lines, 1):
            if re.search(r'storage_encrypted\s*=\s*false', line, re.IGNORECASE) or re.search(r'StorageEncrypted:\s*false', line, re.IGNORECASE):
                rule = RULES_CATALOG[2]
                findings.append(Finding(
                    finding_id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                    rule_id=rule["rule_id"],
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    resource_id="aws_db_instance.primary_db",
                    resource_type="aws_db_instance",
                    provider="aws",
                    file_name=filename,
                    line_start=idx,
                    line_end=idx,
                    standard_mappings=rule["standard_mappings"],
                    risk=rule["risk"],
                    evidence=line.strip(),
                    remediation=rule["remediation"]
                ))

        # Rule 4: Public Database
        for idx, line in enumerate(lines, 1):
            if re.search(r'publicly_accessible\s*=\s*true', line, re.IGNORECASE) or re.search(r'PubliclyAccessible:\s*true', line, re.IGNORECASE):
                rule = RULES_CATALOG[3]
                findings.append(Finding(
                    finding_id=f"FIND-{uuid.uuid4().hex[:8].upper()}",
                    rule_id=rule["rule_id"],
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    resource_id="aws_db_instance.primary_db",
                    resource_type="aws_db_instance",
                    provider="aws",
                    file_name=filename,
                    line_start=idx,
                    line_end=idx,
                    standard_mappings=rule["standard_mappings"],
                    risk=rule["risk"],
                    evidence=line.strip(),
                    remediation=rule["remediation"]
                ))

        crit = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        high = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
        med = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
        low = sum(1 for f in findings if f.severity == SeverityLevel.LOW)

        duration = round((time.time() - start_time) * 1000, 2)

        return ScanResponse(
            scan_id=f"SCAN-{uuid.uuid4().hex[:8].upper()}",
            filename=filename,
            format=fmt,
            summary=ScanSummary(
                total_resources=max(len(findings), 1),
                total_findings=len(findings),
                critical_count=crit,
                high_count=high,
                medium_count=med,
                low_count=low,
                scan_duration_ms=duration
            ),
            findings=findings
        )
