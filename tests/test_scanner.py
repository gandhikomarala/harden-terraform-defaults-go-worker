import pytest
from backend.app.core.rules.engine import SecurityScannerEngine
from backend.app.schemas.models import SeverityLevel

SAMPLE_INSECURE_TF = """
resource "aws_s3_bucket" "data_lake" {
  bucket = "company-analytics-prod"
  acl    = "public-read"
}

resource "aws_security_group_rule" "ssh_ingress" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_db_instance" "primary_db" {
  identifier        = "prod-aurora-cluster"
  engine            = "postgres"
  storage_encrypted = false
  publicly_accessible = true
}
"""

SAMPLE_SECURE_TF = """
resource "aws_s3_bucket" "data_lake" {
  bucket = "company-analytics-prod"
  acl    = "private"
}

resource "aws_security_group_rule" "ssh_ingress" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/16"]
}

resource "aws_db_instance" "primary_db" {
  identifier        = "prod-aurora-cluster"
  engine            = "postgres"
  storage_encrypted = true
  publicly_accessible = false
}
"""

def test_secret_redaction():
    raw_code = 'aws_access_key = "AKIA1234567890ABCDEF"'
    sanitized = SecurityScannerEngine.redact_secrets(raw_code)
    assert "[REDACTED_AWS_KEY]" in sanitized
    assert "AKIA1234567890ABCDEF" not in sanitized

def test_insecure_scan_detects_all_vulnerabilities():
    res = SecurityScannerEngine.scan(SAMPLE_INSECURE_TF, "insecure.tf", "terraform")
    assert res.summary.total_findings >= 3
    assert res.summary.critical_count >= 2
    rule_ids = [f.rule_id for f in res.findings]
    assert "CG-AWS-S3-001" in rule_ids
    assert "CG-AWS-NET-002" in rule_ids
    assert "CG-AWS-RDS-003" in rule_ids

def test_secure_scan_passes_with_zero_findings():
    res = SecurityScannerEngine.scan(SAMPLE_SECURE_TF, "secure.tf", "terraform")
    assert res.summary.total_findings == 0
    assert res.summary.critical_count == 0
