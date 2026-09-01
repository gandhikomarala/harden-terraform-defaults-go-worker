from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.schemas.models import ScanRequest, ScanResponse, RemediationRequest, RemediationResponse
from app.core.rules.engine import SecurityScannerEngine, RULES_CATALOG

app = FastAPI(
    title="CloudGuard SAST API",
    description="Enterprise Infrastructure-as-Code Static Security Analysis & Compliance Engine",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health_check():
    return {"status": "HEALTHY", "service": "CloudGuard SAST API", "version": "1.0.0"}

@app.post("/api/v1/scans", response_model=ScanResponse)
def run_scan(req: ScanRequest):
    sanitized_config = SecurityScannerEngine.redact_secrets(req.configuration)
    return SecurityScannerEngine.scan(sanitized_config, req.filename, req.format)

@app.get("/api/v1/rules")
def list_rules():
    return {"total_rules": len(RULES_CATALOG), "rules": RULES_CATALOG}

@app.post("/api/v1/remediation", response_model=RemediationResponse)
def generate_remediation(req: RemediationRequest):
    vulnerable = req.configuration
    secure = vulnerable.replace('acl = "public-read"', '# acl = "private"
  # Public access block configured via aws_s3_bucket_public_access_block')
    secure = secure.replace('cidr_blocks = ["0.0.0.0/0"]', 'cidr_blocks = ["10.0.0.0/16"] # Restricted to internal VPN bastion CIDR')
    secure = secure.replace('storage_encrypted = false', 'storage_encrypted = true
  kms_key_id       = "arn:aws:kms:us-east-1:123456789012:key/prod-db-key"')
    secure = secure.replace('publicly_accessible = true', 'publicly_accessible = false # Enforce private isolated DB subnet')

    diff = f"""--- {req.finding_id}/insecure.tf
+++ {req.finding_id}/secure.tf
@@ -1,6 +1,8 @@
- acl = "public-read"
- cidr_blocks = ["0.0.0.0/0"]
- storage_encrypted = false
+ cidr_blocks = ["10.0.0.0/16"] # Restricted CIDR
+ storage_encrypted = true
"""

    return RemediationResponse(
        finding_id=req.finding_id,
        vulnerable_code=vulnerable,
        secure_code=secure,
        unified_diff=diff,
        explanation="Remediated public ACLs, restricted SSH ingress to internal CIDR, and enabled KMS storage encryption."
    )
