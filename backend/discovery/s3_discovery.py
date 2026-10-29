"""
S3 Bucket Discovery Module.
Discovers all S3 buckets, checks default server-side encryption,
evaluates public access policies, ACLs, and Public Access Block configuration.
Distinguishes genuinely empty bucket inventories from API permission failures.
"""
import logging
from typing import List, Dict, Any, Tuple
from botocore.exceptions import ClientError, BotoCoreError
from backend.core.aws_client import aws_manager
from backend.models.schemas import S3Bucket, S3PublicAccessBlock
from backend.mock_data import get_mock_s3_buckets

logger = logging.getLogger("cloud_posture.s3_discovery")


def evaluate_bucket_public_access(
    s3_client, bucket_name: str
) -> Tuple[bool, bool, S3PublicAccessBlock, str, str]:
    """
    Evaluates whether an S3 bucket is public via Policy, ACL, or lack of PublicAccessBlock.
    Returns: (is_public, has_public_policy, public_access_block_config, access_policy_label, evidence_summary)
    """
    has_public_policy = False
    has_public_acl = False
    pab_config = S3PublicAccessBlock(configured=False)
    evidence_parts: List[str] = []

    # 1. Check Public Access Block Configuration
    try:
        pab_res = s3_client.get_public_access_block(Bucket=bucket_name)
        pab = pab_res.get("PublicAccessBlockConfiguration", {})
        pab_config = S3PublicAccessBlock(
            block_public_acls=pab.get("BlockPublicAcls", False),
            ignore_public_acls=pab.get("IgnorePublicAcls", False),
            block_public_policy=pab.get("BlockPublicPolicy", False),
            restrict_public_buckets=pab.get("RestrictPublicBuckets", False),
            configured=True,
        )
        if pab_config.block_public_acls and pab_config.block_public_policy:
            evidence_parts.append("Public Access Block enabled")
        else:
            evidence_parts.append("Public Access Block partially or fully disabled")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "NoSuchPublicAccessBlockConfiguration":
            evidence_parts.append("No Public Access Block configured")
        else:
            evidence_parts.append(f"Public Access Block check error ({code})")

    # If all 4 block public access flags are on, public access is prevented
    all_blocks_on = (
        pab_config.block_public_acls
        and pab_config.ignore_public_acls
        and pab_config.block_public_policy
        and pab_config.restrict_public_buckets
    )

    # 2. Check Bucket Policy Status
    if not (pab_config.block_public_policy and pab_config.restrict_public_buckets):
        try:
            policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
            has_public_policy = policy_status.get("PolicyStatus", {}).get("IsPublic", False)
            if has_public_policy:
                evidence_parts.append("Bucket policy grants public access")
            else:
                evidence_parts.append("Bucket policy is private")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "NoSuchBucketPolicy":
                evidence_parts.append("No bucket policy attached")
            elif code != "AccessDenied":
                evidence_parts.append(f"Policy status check ({code})")

    # 3. Check Bucket ACL
    if not (pab_config.block_public_acls and pab_config.ignore_public_acls):
        try:
            acl_res = s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl_res.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    has_public_acl = True
                    evidence_parts.append(f"Public ACL grant detected: {uri.split('/')[-1]}")
                    break
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code != "AccessDenied":
                evidence_parts.append(f"ACL check ({code})")

    # Overall Public evaluation
    is_public = (not all_blocks_on) and (has_public_policy or has_public_acl)
    access_label = "Public" if is_public else "Private"
    evidence_str = "; ".join(evidence_parts) if evidence_parts else "Default access configuration"

    return is_public, has_public_policy, pab_config, access_label, evidence_str


def get_bucket_encryption_details(s3_client, bucket_name: str) -> Tuple[str, str | None]:
    """
    Checks if S3 bucket has default server-side encryption enabled (SSE-S3 or SSE-KMS).
    Returns: (encryption_status, kms_key_id)
    """
    try:
        enc_res = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = enc_res.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            apply_action = rules[0].get("ApplyServerSideEncryptionByDefault", {})
            sse_algorithm = apply_action.get("SSEAlgorithm", "")
            kms_key = apply_action.get("KMSMasterKeyId")

            if sse_algorithm == "aws:kms":
                return "SSE-KMS", kms_key
            elif sse_algorithm == "AES256":
                return "SSE-S3 (AES256)", None
            elif sse_algorithm:
                return sse_algorithm, kms_key

        return "Unencrypted", None
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchServerSideEncryptionConfiguration"):
            return "Unencrypted", None
        if code == "AccessDenied":
            return "Unknown (AccessDenied)", None
        logger.debug(f"Encryption check error for {bucket_name}: {code}")
        return f"Unknown ({code})", None


def discover_s3_resources() -> Tuple[List[S3Bucket], List[str]]:
    """
    Discovers all S3 buckets in the AWS account, evaluating encryption and public access.
    Returns: (discovered_buckets, scan_errors)
    """
    if aws_manager.is_mock_mode():
        logger.info("Operating in Mock/Simulation mode: returning realistic mock S3 data.")
        return get_mock_s3_buckets(), []

    discovered_buckets: List[S3Bucket] = []
    scan_errors: List[str] = []

    try:
        s3 = aws_manager.get_client("s3")
        response = s3.list_buckets()
        buckets_list = response.get("Buckets", [])

        for b in buckets_list:
            name = b.get("Name", "")
            creation_date = b.get("CreationDate")
            date_str = creation_date.isoformat() if creation_date else None

            # 1. Resolve Bucket Region
            region = "us-east-1"
            try:
                loc_res = s3.get_bucket_location(Bucket=name)
                loc_constraint = loc_res.get("LocationConstraint")
                if loc_constraint:
                    region = "eu-west-1" if loc_constraint == "EU" else loc_constraint
                else:
                    region = "us-east-1"
            except ClientError as e:
                logger.debug(f"Location check error for {name}: {e}")

            # Regional S3 client for bucket-level API operations to avoid 301 redirects
            regional_s3 = aws_manager.get_client("s3", region_name=region)

            # 2. Check Encryption
            enc_status, kms_id = get_bucket_encryption_details(regional_s3, name)

            # 3. Check Public Access
            is_pub, has_policy, pab_cfg, access_label, evidence_notes = evaluate_bucket_public_access(
                regional_s3, name
            )

            # 4. Check Versioning
            versioning_status = "Disabled"
            try:
                ver_res = regional_s3.get_bucket_versioning(Bucket=name)
                versioning_status = ver_res.get("Status", "Disabled")
            except ClientError as e:
                logger.debug(f"Versioning check error for {name}: {e}")

            discovered_buckets.append(
                S3Bucket(
                    bucket_name=name,
                    region=region,
                    creation_date=date_str,
                    encryption_status=enc_status,
                    kms_key_id=kms_id,
                    access_policy=access_label,
                    public_access_block=pab_cfg,
                    has_public_policy=has_policy,
                    has_public_acl=is_pub and not has_policy,
                    versioning_status=versioning_status,
                    evidence_notes=evidence_notes,
                )
            )

    except (ClientError, BotoCoreError) as e:
        err_msg = f"Failed to list S3 buckets: {e}"
        logger.error(err_msg)
        scan_errors.append(err_msg)
    except Exception as e:
        err_msg = f"Unexpected error discovering S3 buckets: {e}"
        logger.error(err_msg)
        scan_errors.append(err_msg)

    return discovered_buckets, scan_errors


def discover_s3_buckets() -> List[S3Bucket]:
    """Legacy compatibility wrapper returning discovered buckets."""
    buckets, _ = discover_s3_resources()
    return buckets
