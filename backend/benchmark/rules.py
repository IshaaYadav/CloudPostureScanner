"""
CIS AWS Foundations Benchmark Rule Implementations.
Reference: CIS AWS Foundations Benchmark v1.4.0 (with v3.0.0 control mappings):
- CIS 1.4: Root account access keys (v1.4.0 Section 1.4 / v3.0.0 Section 1.4)
- CIS 1.5: Root account MFA enabled (v1.4.0 Section 1.5 / v3.0.0 Section 1.5)
- CIS 2.1.1: S3 bucket public accessibility (v1.4.0 Section 2.1.1 / v3.0.0 Section 2.1.4)
- CIS 2.1.2: S3 bucket default encryption (v1.4.0 Section 2.1.2 / v3.0.0 Section 2.1.1)
- CIS 2.1.3: S3 bucket versioning (v1.4.0 Section 2.1.3)
- CIS 3.1: CloudTrail multi-region active logging (v1.4.0 Section 3.1 / v3.0.0 Section 3.1)
- CIS 4.1: Security group unrestricted SSH (port 22) (v1.4.0 Section 4.1 / v3.0.0 Section 5.1)
- CIS 4.2: Security group unrestricted RDP (port 3389) (v1.4.0 Section 4.2 / v3.0.0 Section 5.2)

Scope and Limitation Notice:
These automated rules provide heuristic posture assessments for educational and operational visibility.
They do not constitute a formal audit or official certification under CIS standards.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from backend.models.schemas import (
    CISCheckResult,
    S3Bucket,
    EC2Instance,
    SecurityGroupSummary,
)


def _current_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def check_s3_public_access(bucket: S3Bucket) -> CISCheckResult:
    """CIS 2.1.1 (v3.0.0 2.1.4): Ensure S3 Bucket Access is Not Public."""
    pab = bucket.public_access_block

    # Check for evaluation errors
    if bucket.evidence_notes and "AccessDenied" in bucket.evidence_notes:
        return CISCheckResult(
            check_id="CIS-2.1.1",
            title="Ensure S3 Bucket Access is Not Public",
            category="S3",
            severity="CRITICAL",
            status="ERROR",
            resource_id=bucket.bucket_name,
            resource_type="AWS::S3::Bucket",
            evidence=f"Could not verify public access settings for '{bucket.bucket_name}': {bucket.evidence_notes}.",
            remediation="Ensure scanner has 's3:GetBucketPolicyStatus', 's3:GetPublicAccessBlock', and 's3:GetBucketAcl' permissions.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 2.1.1 (v3.0.0 - 2.1.4)",
            timestamp=_current_timestamp(),
            error_details=bucket.evidence_notes,
        )

    is_public = (bucket.access_policy == "Public") or bucket.has_public_policy or bucket.has_public_acl

    if is_public:
        reasons = []
        if bucket.has_public_policy:
            reasons.append("public bucket policy allows world access")
        if bucket.has_public_acl:
            reasons.append("ACL grants public Read/Write permissions")
        if not (pab.block_public_acls and pab.block_public_policy):
            reasons.append("Public Access Block is disabled or incomplete")

        evidence_str = (
            f"Bucket '{bucket.bucket_name}' in region '{bucket.region}' is publicly accessible. "
            f"Findings: {'; '.join(reasons)}."
        )
        return CISCheckResult(
            check_id="CIS-2.1.1",
            title="Ensure S3 Bucket Access is Not Public",
            category="S3",
            severity="CRITICAL",
            status="FAIL",
            resource_id=bucket.bucket_name,
            resource_type="AWS::S3::Bucket",
            evidence=evidence_str,
            remediation=(
                f"aws s3api put-public-access-block --bucket {bucket.bucket_name} "
                '--public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,'
                'BlockPublicPolicy=true,RestrictPublicBuckets=true"'
            ),
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 2.1.1 (v3.0.0 - 2.1.4)",
            timestamp=_current_timestamp(),
        )
    else:
        return CISCheckResult(
            check_id="CIS-2.1.1",
            title="Ensure S3 Bucket Access is Not Public",
            category="S3",
            severity="CRITICAL",
            status="PASS",
            resource_id=bucket.bucket_name,
            resource_type="AWS::S3::Bucket",
            evidence=f"Bucket '{bucket.bucket_name}' has private access settings and Public Access Block enabled.",
            remediation="No remediation necessary.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 2.1.1 (v3.0.0 - 2.1.4)",
            timestamp=_current_timestamp(),
        )


def check_s3_encryption(bucket: S3Bucket) -> CISCheckResult:
    """CIS 2.1.2 (v3.0.0 2.1.1): Ensure S3 Bucket Default Encryption is Enabled."""
    if "AccessDenied" in bucket.encryption_status or "Unknown" in bucket.encryption_status:
        return CISCheckResult(
            check_id="CIS-2.1.2",
            title="Ensure S3 Bucket Default Encryption is Enabled",
            category="S3",
            severity="HIGH",
            status="ERROR",
            resource_id=bucket.bucket_name,
            resource_type="AWS::S3::Bucket",
            evidence=f"Could not verify encryption configuration for bucket '{bucket.bucket_name}': {bucket.encryption_status}.",
            remediation="Grant 's3:GetEncryptionConfiguration' permission to the scanner IAM principal.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 2.1.2 (v3.0.0 - 2.1.1)",
            timestamp=_current_timestamp(),
            error_details=bucket.encryption_status,
        )

    is_encrypted = bucket.encryption_status != "Unencrypted"

    if not is_encrypted:
        return CISCheckResult(
            check_id="CIS-2.1.2",
            title="Ensure S3 Bucket Default Encryption is Enabled",
            category="S3",
            severity="HIGH",
            status="FAIL",
            resource_id=bucket.bucket_name,
            resource_type="AWS::S3::Bucket",
            evidence=f"Bucket '{bucket.bucket_name}' has no default server-side encryption configured. Data at rest is unprotected.",
            remediation=(
                f"aws s3api put-bucket-encryption --bucket {bucket.bucket_name} "
                '--server-side-encryption-configuration \'{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}\''
            ),
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 2.1.2 (v3.0.0 - 2.1.1)",
            timestamp=_current_timestamp(),
        )
    else:
        return CISCheckResult(
            check_id="CIS-2.1.2",
            title="Ensure S3 Bucket Default Encryption is Enabled",
            category="S3",
            severity="HIGH",
            status="PASS",
            resource_id=bucket.bucket_name,
            resource_type="AWS::S3::Bucket",
            evidence=f"Bucket '{bucket.bucket_name}' is encrypted at rest using {bucket.encryption_status}.",
            remediation="No remediation necessary.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 2.1.2 (v3.0.0 - 2.1.1)",
            timestamp=_current_timestamp(),
        )


def check_s3_versioning(bucket: S3Bucket) -> CISCheckResult:
    """CIS 2.1.3: Ensure S3 Bucket Versioning is Enabled."""
    is_versioned = (bucket.versioning_status == "Enabled")
    if not is_versioned:
        return CISCheckResult(
            check_id="CIS-2.1.3",
            title="Ensure S3 Bucket Versioning is Enabled",
            category="S3",
            severity="MEDIUM",
            status="WARNING",
            resource_id=bucket.bucket_name,
            resource_type="AWS::S3::Bucket",
            evidence=f"Bucket '{bucket.bucket_name}' has versioning status '{bucket.versioning_status}'. Objects are vulnerable to accidental deletion or ransomware overwrites.",
            remediation=f"aws s3api put-bucket-versioning --bucket {bucket.bucket_name} --versioning-configuration Status=Enabled",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 2.1.3",
            timestamp=_current_timestamp(),
        )
    else:
        return CISCheckResult(
            check_id="CIS-2.1.3",
            title="Ensure S3 Bucket Versioning is Enabled",
            category="S3",
            severity="MEDIUM",
            status="PASS",
            resource_id=bucket.bucket_name,
            resource_type="AWS::S3::Bucket",
            evidence=f"Bucket '{bucket.bucket_name}' has versioning enabled.",
            remediation="No remediation necessary.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 2.1.3",
            timestamp=_current_timestamp(),
        )


def check_sg_ssh(sg: SecurityGroupSummary) -> CISCheckResult:
    """CIS 4.1 (v3.0.0 5.1): Ensure No Security Groups Allow Ingress from 0.0.0.0/0 or ::/0 to Port 22."""
    if sg.allows_all_ssh:
        return CISCheckResult(
            check_id="CIS-4.1",
            title="Ensure No Security Groups Allow Ingress to SSH (Port 22) from 0.0.0.0/0 or ::/0",
            category="EC2 / Networking",
            severity="HIGH",
            status="FAIL",
            resource_id=sg.group_id,
            resource_type="AWS::EC2::SecurityGroup",
            evidence=(
                f"Security Group '{sg.group_name}' ({sg.group_id}) allows inbound TCP port 22 (SSH) "
                "from unrestricted sources (0.0.0.0/0 or ::/0). Exposed to internet-wide brute-force attacks."
            ),
            remediation=f"aws ec2 revoke-security-group-ingress --group-id {sg.group_id} --protocol tcp --port 22 --cidr 0.0.0.0/0",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 4.1 (v3.0.0 - 5.1)",
            timestamp=_current_timestamp(),
        )
    else:
        return CISCheckResult(
            check_id="CIS-4.1",
            title="Ensure No Security Groups Allow Ingress to SSH (Port 22) from 0.0.0.0/0 or ::/0",
            category="EC2 / Networking",
            severity="HIGH",
            status="PASS",
            resource_id=sg.group_id,
            resource_type="AWS::EC2::SecurityGroup",
            evidence=f"Security Group '{sg.group_name}' ({sg.group_id}) does not expose port 22 to unrestricted CIDRs.",
            remediation="No remediation necessary.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 4.1 (v3.0.0 - 5.1)",
            timestamp=_current_timestamp(),
        )


def check_sg_rdp(sg: SecurityGroupSummary) -> CISCheckResult:
    """CIS 4.2 (v3.0.0 5.2): Ensure No Security Groups Allow Ingress from 0.0.0.0/0 or ::/0 to Port 3389."""
    if sg.allows_all_rdp:
        return CISCheckResult(
            check_id="CIS-4.2",
            title="Ensure No Security Groups Allow Ingress to RDP (Port 3389) from 0.0.0.0/0 or ::/0",
            category="EC2 / Networking",
            severity="CRITICAL",
            status="FAIL",
            resource_id=sg.group_id,
            resource_type="AWS::EC2::SecurityGroup",
            evidence=(
                f"Security Group '{sg.group_name}' ({sg.group_id}) allows inbound TCP port 3389 (RDP) "
                "from unrestricted sources (0.0.0.0/0 or ::/0). Critical vulnerability to remote exploits and ransomware."
            ),
            remediation=f"aws ec2 revoke-security-group-ingress --group-id {sg.group_id} --protocol tcp --port 3389 --cidr 0.0.0.0/0",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 4.2 (v3.0.0 - 5.2)",
            timestamp=_current_timestamp(),
        )
    else:
        return CISCheckResult(
            check_id="CIS-4.2",
            title="Ensure No Security Groups Allow Ingress to RDP (Port 3389) from 0.0.0.0/0 or ::/0",
            category="EC2 / Networking",
            severity="CRITICAL",
            status="PASS",
            resource_id=sg.group_id,
            resource_type="AWS::EC2::SecurityGroup",
            evidence=f"Security Group '{sg.group_name}' ({sg.group_id}) does not expose port 3389 to unrestricted CIDRs.",
            remediation="No remediation necessary.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 4.2 (v3.0.0 - 5.2)",
            timestamp=_current_timestamp(),
        )


def check_iam_root_mfa(
    mfa_enabled: Optional[bool], account_id: str, error_msg: Optional[str] = None
) -> CISCheckResult:
    """CIS 1.5 (v3.0.0 1.5): Ensure MFA is Enabled for the 'root' User Account."""
    if error_msg is not None or mfa_enabled is None:
        return CISCheckResult(
            check_id="CIS-1.5",
            title="Ensure MFA is Enabled for the 'root' User Account",
            category="IAM",
            severity="CRITICAL",
            status="ERROR",
            resource_id=f"arn:aws:iam::{account_id}:root",
            resource_type="AWS::IAM::RootAccount",
            evidence=f"Unable to query IAM account summary for account {account_id}: {error_msg or 'Permission denied'}.",
            remediation="Grant 'iam:GetAccountSummary' to the scanner IAM principal.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 1.5 (v3.0.0 - 1.5)",
            timestamp=_current_timestamp(),
            error_details=error_msg,
        )

    if not mfa_enabled:
        return CISCheckResult(
            check_id="CIS-1.5",
            title="Ensure MFA is Enabled for the 'root' User Account",
            category="IAM",
            severity="CRITICAL",
            status="FAIL",
            resource_id=f"arn:aws:iam::{account_id}:root",
            resource_type="AWS::IAM::RootAccount",
            evidence=f"The root user account for AWS account {account_id} does NOT have Multi-Factor Authentication (MFA) enabled.",
            remediation="Sign into the AWS Management Console as the root user. Navigate to IAM > Security Credentials > Assign MFA Device to configure a virtual or hardware token.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 1.5 (v3.0.0 - 1.5)",
            timestamp=_current_timestamp(),
        )
    else:
        return CISCheckResult(
            check_id="CIS-1.5",
            title="Ensure MFA is Enabled for the 'root' User Account",
            category="IAM",
            severity="CRITICAL",
            status="PASS",
            resource_id=f"arn:aws:iam::{account_id}:root",
            resource_type="AWS::IAM::RootAccount",
            evidence=f"MFA is actively enabled for the root account of AWS account {account_id}.",
            remediation="No remediation necessary.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 1.5 (v3.0.0 - 1.5)",
            timestamp=_current_timestamp(),
        )


def check_iam_root_access_keys(
    keys_present: Optional[bool], account_id: str, error_msg: Optional[str] = None
) -> CISCheckResult:
    """CIS 1.4 (v3.0.0 1.4): Ensure No Access Keys Exist for the Root User Account."""
    if error_msg is not None or keys_present is None:
        return CISCheckResult(
            check_id="CIS-1.4",
            title="Ensure No Access Keys Exist for the 'root' User Account",
            category="IAM",
            severity="CRITICAL",
            status="ERROR",
            resource_id=f"arn:aws:iam::{account_id}:root",
            resource_type="AWS::IAM::RootAccount",
            evidence=f"Unable to query IAM account summary for account {account_id}: {error_msg or 'Permission denied'}.",
            remediation="Grant 'iam:GetAccountSummary' to the scanner IAM principal.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 1.4 (v3.0.0 - 1.4)",
            timestamp=_current_timestamp(),
            error_details=error_msg,
        )

    if keys_present:
        return CISCheckResult(
            check_id="CIS-1.4",
            title="Ensure No Access Keys Exist for the 'root' User Account",
            category="IAM",
            severity="CRITICAL",
            status="FAIL",
            resource_id=f"arn:aws:iam::{account_id}:root",
            resource_type="AWS::IAM::RootAccount",
            evidence=f"Active access keys exist for the root account in {account_id}. Root keys provide unrestricted access and should never be created or used for daily operations.",
            remediation="Sign into the AWS Console as root, navigate to IAM > Security credentials, locate 'Access keys' and delete them.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 1.4 (v3.0.0 - 1.4)",
            timestamp=_current_timestamp(),
        )
    else:
        return CISCheckResult(
            check_id="CIS-1.4",
            title="Ensure No Access Keys Exist for the 'root' User Account",
            category="IAM",
            severity="CRITICAL",
            status="PASS",
            resource_id=f"arn:aws:iam::{account_id}:root",
            resource_type="AWS::IAM::RootAccount",
            evidence=f"No active access keys exist for the root account in {account_id}.",
            remediation="No remediation necessary.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 1.4 (v3.0.0 - 1.4)",
            timestamp=_current_timestamp(),
        )


def check_cloudtrail_enabled(
    trails: Optional[List[Dict[str, Any]]], account_id: str, error_msg: Optional[str] = None
) -> CISCheckResult:
    """CIS 3.1 (v3.0.0 3.1): Ensure CloudTrail is Enabled Across All Regions and Actively Logging."""
    if error_msg is not None or trails is None:
        return CISCheckResult(
            check_id="CIS-3.1",
            title="Ensure CloudTrail is Enabled Across All Regions",
            category="Logging",
            severity="HIGH",
            status="ERROR",
            resource_id=f"arn:aws:cloudtrail::{account_id}:trail/*",
            resource_type="AWS::CloudTrail::Trail",
            evidence=f"Unable to retrieve CloudTrail configuration for account {account_id}: {error_msg or 'Permission denied'}.",
            remediation="Grant 'cloudtrail:DescribeTrails' and 'cloudtrail:GetTrailStatus' to the scanner IAM principal.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 3.1 (v3.0.0 - 3.1)",
            timestamp=_current_timestamp(),
            error_details=error_msg,
        )

    active_multi_region_trail = None
    existing_trails_summary = []

    for trail in trails:
        name = trail.get("name", "unnamed")
        is_multi = trail.get("is_multi_region", False)
        is_log = trail.get("is_logging", False)
        existing_trails_summary.append(f"Trail '{name}' (MultiRegion={is_multi}, Logging={is_log})")
        if is_multi and is_log:
            active_multi_region_trail = trail
            break

    if not active_multi_region_trail:
        evidence_detail = (
            f"Existing trails: {', '.join(existing_trails_summary)}."
            if existing_trails_summary
            else "No CloudTrail trails configured."
        )
        return CISCheckResult(
            check_id="CIS-3.1",
            title="Ensure CloudTrail is Enabled Across All Regions",
            category="Logging",
            severity="HIGH",
            status="FAIL",
            resource_id=f"arn:aws:cloudtrail::{account_id}:trail/*",
            resource_type="AWS::CloudTrail::Trail",
            evidence=(
                "No active multi-region CloudTrail was found logging management events across all regions. "
                f"{evidence_detail} Actions in unmonitored regions cannot be audited."
            ),
            remediation=(
                "aws cloudtrail create-trail --name multi-region-security-trail "
                "--s3-bucket-name <your-audit-bucket> --is-multi-region-trail && "
                "aws cloudtrail start-logging --name multi-region-security-trail"
            ),
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 3.1 (v3.0.0 - 3.1)",
            timestamp=_current_timestamp(),
        )
    else:
        trail_name = active_multi_region_trail.get("name", "unknown")
        return CISCheckResult(
            check_id="CIS-3.1",
            title="Ensure CloudTrail is Enabled Across All Regions",
            category="Logging",
            severity="HIGH",
            status="PASS",
            resource_id=f"arn:aws:cloudtrail::{account_id}:trail/{trail_name}",
            resource_type="AWS::CloudTrail::Trail",
            evidence=f"CloudTrail '{trail_name}' is enabled and actively logging management events across all AWS regions.",
            remediation="No remediation necessary.",
            reference="CIS AWS Foundations Benchmark v1.4.0 - Section 3.1 (v3.0.0 - 3.1)",
            timestamp=_current_timestamp(),
        )
