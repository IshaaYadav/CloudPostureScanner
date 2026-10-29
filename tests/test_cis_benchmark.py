"""
Tests for CIS AWS Foundations Benchmark Rules and Engine.
Verifies Pass, Fail, and Permission Error states across all 5 required security checks.
"""
import pytest
from backend.models.schemas import (
    S3Bucket,
    S3PublicAccessBlock,
    SecurityGroupSummary,
)
from backend.benchmark.rules import (
    check_s3_public_access,
    check_s3_encryption,
    check_s3_versioning,
    check_sg_ssh,
    check_sg_rdp,
    check_iam_root_mfa,
    check_iam_root_access_keys,
    check_cloudtrail_enabled,
)
from backend.benchmark.engine import benchmark_engine


def test_cis_check_s3_public_access():
    # 1. Public bucket should FAIL
    pub_bucket = S3Bucket(
        bucket_name="leak-bucket",
        region="us-east-1",
        access_policy="Public",
        has_public_policy=True,
    )
    res = check_s3_public_access(pub_bucket)
    assert res.check_id == "CIS-2.1.1"
    assert res.status == "FAIL"
    assert "publicly accessible" in res.evidence

    # 2. Private bucket with PAB should PASS
    priv_bucket = S3Bucket(
        bucket_name="safe-bucket",
        region="us-east-1",
        access_policy="Private",
        public_access_block=S3PublicAccessBlock(
            block_public_acls=True,
            ignore_public_acls=True,
            block_public_policy=True,
            restrict_public_buckets=True,
        ),
    )
    res_safe = check_s3_public_access(priv_bucket)
    assert res_safe.status == "PASS"

    # 3. AccessDenied on PAB evaluation should yield ERROR, not FAIL
    err_bucket = S3Bucket(
        bucket_name="locked-bucket",
        region="us-east-1",
        evidence_notes="Public Access Block check error (AccessDenied)",
    )
    res_err = check_s3_public_access(err_bucket)
    assert res_err.status == "ERROR"
    assert res_err.error_details is not None


def test_cis_check_s3_encryption():
    # 1. Unencrypted bucket should FAIL
    unencrypted = S3Bucket(
        bucket_name="raw-data",
        region="us-west-2",
        encryption_status="Unencrypted",
    )
    res = check_s3_encryption(unencrypted)
    assert res.check_id == "CIS-2.1.2"
    assert res.status == "FAIL"

    # 2. Encrypted bucket should PASS
    encrypted = S3Bucket(
        bucket_name="enc-data",
        region="us-west-2",
        encryption_status="SSE-S3 (AES256)",
    )
    res_enc = check_s3_encryption(encrypted)
    assert res_enc.status == "PASS"

    # 3. AccessDenied should yield ERROR
    denied = S3Bucket(
        bucket_name="denied-data",
        region="us-west-2",
        encryption_status="Unknown (AccessDenied)",
    )
    res_denied = check_s3_encryption(denied)
    assert res_denied.status == "ERROR"


def test_cis_check_sg_ssh_and_rdp():
    # 1. Open to 0.0.0.0/0 or ::/0 should FAIL
    sg_bad = SecurityGroupSummary(
        group_id="sg-danger",
        group_name="danger-sg",
        allows_all_ssh=True,
        allows_all_rdp=True,
    )
    res_ssh = check_sg_ssh(sg_bad)
    assert res_ssh.check_id == "CIS-4.1"
    assert res_ssh.status == "FAIL"

    res_rdp = check_sg_rdp(sg_bad)
    assert res_rdp.check_id == "CIS-4.2"
    assert res_rdp.status == "FAIL"

    # 2. Restricted security group should PASS
    sg_good = SecurityGroupSummary(
        group_id="sg-clean",
        group_name="clean-sg",
        allows_all_ssh=False,
        allows_all_rdp=False,
    )
    assert check_sg_ssh(sg_good).status == "PASS"
    assert check_sg_rdp(sg_good).status == "PASS"


def test_cis_check_iam_root_mfa():
    # 1. MFA disabled should FAIL
    res_fail = check_iam_root_mfa(mfa_enabled=False, account_id="111222333444")
    assert res_fail.check_id == "CIS-1.5"
    assert res_fail.status == "FAIL"

    # 2. MFA enabled should PASS
    res_pass = check_iam_root_mfa(mfa_enabled=True, account_id="111222333444")
    assert res_pass.status == "PASS"

    # 3. Missing permissions should return ERROR
    res_err = check_iam_root_mfa(mfa_enabled=None, account_id="111222333444", error_msg="AccessDenied: User not authorized")
    assert res_err.status == "ERROR"
    assert "AccessDenied" in res_err.error_details


def test_cis_check_cloudtrail():
    # 1. Single-region or not logging should FAIL
    trails_bad = [{"name": "single-region", "is_multi_region": False, "is_logging": True}]
    res_fail = check_cloudtrail_enabled(trails_bad, "111222333444")
    assert res_fail.check_id == "CIS-3.1"
    assert res_fail.status == "FAIL"

    # 2. Multi-region trail that is actively logging should PASS
    trails_good = [{"name": "global-trail", "is_multi_region": True, "is_logging": True}]
    res_pass = check_cloudtrail_enabled(trails_good, "111222333444")
    assert res_pass.status == "PASS"

    # 3. Trail exists but is NOT logging should FAIL
    trails_inactive = [{"name": "paused-trail", "is_multi_region": True, "is_logging": False}]
    res_inactive = check_cloudtrail_enabled(trails_inactive, "111222333444")
    assert res_inactive.status == "FAIL"

    # 4. Permission error should return ERROR
    res_err = check_cloudtrail_enabled(None, "111222333444", error_msg="UnauthorizedOperation")
    assert res_err.status == "ERROR"


def test_benchmark_engine_summary_computation():
    buckets = [
        S3Bucket(bucket_name="b1", region="us-east-1", encryption_status="SSE-S3", access_policy="Private"),
        S3Bucket(bucket_name="b2", region="us-east-1", encryption_status="Unencrypted", access_policy="Public"),
    ]
    sgs = [
        SecurityGroupSummary(group_id="sg-1", group_name="sg-1", allows_all_ssh=False, allows_all_rdp=False),
        SecurityGroupSummary(group_id="sg-2", group_name="sg-2", allows_all_ssh=True, allows_all_rdp=False),
    ]

    results, summary = benchmark_engine.run_all_checks(buckets=buckets, security_groups=sgs)

    assert summary.total_checks == len(results)
    assert summary.passed_checks + summary.failed_checks + summary.warning_checks + summary.error_checks == summary.total_checks
    assert 0.0 <= summary.compliance_score_percent <= 100.0
