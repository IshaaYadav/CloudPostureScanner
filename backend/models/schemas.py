"""
Pydantic schemas and data models for Cloud Posture Scanner.
"""
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class SecurityGroupRule(BaseModel):
    ip_protocol: str
    from_port: Optional[int] = None
    to_port: Optional[int] = None
    cidr_ip: Optional[str] = None
    description: Optional[str] = None


class SecurityGroupSummary(BaseModel):
    group_id: str
    group_name: str
    description: Optional[str] = None
    vpc_id: Optional[str] = None
    allows_all_ssh: bool = False
    allows_all_rdp: bool = False
    open_inbound_rules: List[str] = Field(default_factory=list)


class EC2Instance(BaseModel):
    instance_id: str
    name: Optional[str] = "Unnamed"
    instance_type: str
    region: str
    state: str
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    vpc_id: Optional[str] = None
    security_groups: List[SecurityGroupSummary] = Field(default_factory=list)
    launch_time: Optional[str] = None


class S3PublicAccessBlock(BaseModel):
    block_public_acls: bool = False
    ignore_public_acls: bool = False
    block_public_policy: bool = False
    restrict_public_buckets: bool = False
    configured: bool = False


class S3Bucket(BaseModel):
    bucket_name: str
    region: str
    creation_date: Optional[str] = None
    encryption_status: str = "Unencrypted"  # "SSE-S3 (AES256)", "SSE-KMS", "Unencrypted"
    kms_key_id: Optional[str] = None
    access_policy: str = "Private"          # "Public", "Private"
    public_access_block: S3PublicAccessBlock = Field(default_factory=S3PublicAccessBlock)
    has_public_policy: bool = False
    has_public_acl: bool = False
    versioning_status: str = "Disabled"    # "Enabled", "Suspended", "Disabled"
    evidence_notes: Optional[str] = None


class CISCheckResult(BaseModel):
    check_id: str                          # e.g., "CIS-2.1.1", "CIS-2.1.2", "CIS-1.5"
    title: str
    category: str                          # "IAM", "S3", "EC2 / Networking", "Logging"
    severity: str                          # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    status: str                            # "PASS", "FAIL", "ERROR", "UNKNOWN", "NOT_APPLICABLE"
    resource_id: str                       # e.g., "my-bucket", "sg-12345", "root"
    resource_type: str                     # "AWS::S3::Bucket", "AWS::EC2::SecurityGroup", "AWS::IAM::RootAccount"
    evidence: str                          # Concrete technical finding
    remediation: str                       # Exact CLI or console step to remediate
    reference: Optional[str] = None        # CIS benchmark section
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error_details: Optional[str] = None    # Populated if status is ERROR or UNKNOWN


class CISSummary(BaseModel):
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    warning_checks: int = 0
    error_checks: int = 0
    unknown_checks: int = 0
    compliance_score_percent: float = 0.0
    critical_failures: int = 0
    high_failures: int = 0
    medium_failures: int = 0
    low_failures: int = 0


class StorageMetadata(BaseModel):
    destination: str                       # "AWS-S3" or "Local-Storage"
    location: str                          # "s3://<bucket>/scans/..." or local file path
    status: str                            # "SUCCESS" or "FAILED"
    encrypted: bool = True
    error_message: Optional[str] = None


class ScanReport(BaseModel):
    scan_id: str
    aws_account_id: str
    start_time: str
    completion_time: str
    timestamp: str                         # Maintained for compatibility
    status: str = "COMPLETED"              # "COMPLETED", "PARTIAL", "FAILED"
    mode: str                              # "LIVE_AWS" or "DEMO_SIMULATION"
    target_regions: List[str]
    instances: List[EC2Instance] = Field(default_factory=list)
    buckets: List[S3Bucket] = Field(default_factory=list)
    cis_results: List[CISCheckResult] = Field(default_factory=list)
    summary: CISSummary = Field(default_factory=CISSummary)
    scan_errors: List[str] = Field(default_factory=list)
    storage: StorageMetadata = Field(
        default_factory=lambda: StorageMetadata(
            destination="Local-Storage",
            location="./data/latest_scan.json",
            status="SUCCESS",
            encrypted=True,
        )
    )


class ScanSummaryItem(BaseModel):
    scan_id: str
    timestamp: str
    completion_time: Optional[str] = None
    aws_account_id: Optional[str] = None
    mode: str
    status: str = "COMPLETED"
    compliance_score: float = 0.0
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    error_checks: int = 0
    instances_count: int = 0
    buckets_count: int = 0
    storage_destination: str
    storage_location: str


class AWSConfigPayload(BaseModel):
    """Runtime configuration payload - never exposes or accepts permanent secret keys."""
    aws_profile: Optional[str] = None
    aws_region: Optional[str] = None
    scan_regions: Optional[List[str]] = None
    s3_storage_bucket: Optional[str] = None
    use_mock: Optional[bool] = None
