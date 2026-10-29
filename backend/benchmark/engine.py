"""
CIS AWS Benchmark Evaluation Engine.
Orchestrates rule execution, gathers live/mock telemetry, and computes compliance metrics.
Properly handles permission errors as ERROR states without falling back to mock data in live mode.
"""
import logging
from typing import List, Dict, Any, Tuple, Optional
from botocore.exceptions import ClientError, BotoCoreError
from backend.core.aws_client import aws_manager
from backend.models.schemas import (
    CISCheckResult,
    CISSummary,
    S3Bucket,
    SecurityGroupSummary,
    EC2Instance,
)
from backend.mock_data import get_mock_iam_posture, get_mock_cloudtrail_posture
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

logger = logging.getLogger("cloud_posture.benchmark_engine")


class CISBenchmarkEngine:
    """Executes CIS AWS Foundations Benchmark checks against discovered cloud infrastructure."""

    def __init__(self):
        pass

    def _fetch_iam_posture(self) -> Dict[str, Any]:
        """Fetches live IAM posture or mock fallback."""
        if aws_manager.is_mock_mode():
            data = get_mock_iam_posture()
            data["error"] = None
            return data

        account_id = aws_manager.get_account_id()
        try:
            iam = aws_manager.get_client("iam")
            summary = iam.get_account_summary().get("SummaryMap", {})
            mfa_enabled = bool(summary.get("AccountMFAEnabled", 0))
            access_keys_present = bool(summary.get("AccountAccessKeysPresent", 0))
            return {
                "root_mfa_enabled": mfa_enabled,
                "root_access_keys_present": access_keys_present,
                "account_id": account_id,
                "error": None,
            }
        except (ClientError, BotoCoreError) as e:
            err_msg = f"IAM get_account_summary failed: {e}"
            logger.warning(err_msg)
            return {
                "root_mfa_enabled": None,
                "root_access_keys_present": None,
                "account_id": account_id,
                "error": err_msg,
            }
        except Exception as e:
            err_msg = f"Unexpected error retrieving IAM summary: {e}"
            logger.error(err_msg)
            return {
                "root_mfa_enabled": None,
                "root_access_keys_present": None,
                "account_id": account_id,
                "error": err_msg,
            }

    def _fetch_cloudtrail_posture(self) -> Dict[str, Any]:
        """Fetches live CloudTrail posture or mock fallback."""
        if aws_manager.is_mock_mode():
            data = get_mock_cloudtrail_posture()
            data["error"] = None
            return data

        try:
            cloudtrail = aws_manager.get_client("cloudtrail")
            trails_res = cloudtrail.describe_trails(includeShadowTrails=False)
            trails_list = []

            for trail in trails_res.get("trailList", []):
                name = trail.get("Name", "")
                is_multi_region = trail.get("IsMultiRegionTrail", False)
                s3_bucket = trail.get("S3BucketName", "")
                home_region = trail.get("HomeRegion", "")

                # Check if trail is actively logging
                is_logging = False
                try:
                    status_res = cloudtrail.get_trail_status(Name=name)
                    is_logging = status_res.get("IsLogging", False)
                except ClientError as e:
                    logger.debug(f"Trail status check error for {name}: {e}")

                trails_list.append({
                    "name": name,
                    "is_multi_region": is_multi_region,
                    "is_logging": is_logging,
                    "s3_bucket": s3_bucket,
                    "home_region": home_region,
                })

            return {"trails": trails_list, "error": None}
        except (ClientError, BotoCoreError) as e:
            err_msg = f"CloudTrail describe_trails failed: {e}"
            logger.warning(err_msg)
            return {"trails": None, "error": err_msg}
        except Exception as e:
            err_msg = f"Unexpected error retrieving CloudTrail trails: {e}"
            logger.error(err_msg)
            return {"trails": None, "error": err_msg}

    def run_all_checks(
        self,
        buckets: List[S3Bucket],
        security_groups: List[SecurityGroupSummary],
        instances: List[EC2Instance] = None,
    ) -> Tuple[List[CISCheckResult], CISSummary]:
        """
        Executes CIS checks across all discovered resources and returns:
        (cis_results, summary)
        """
        account_id = aws_manager.get_account_id()
        results: List[CISCheckResult] = []

        # 1. IAM Checks
        iam_data = self._fetch_iam_posture()
        results.append(
            check_iam_root_mfa(
                iam_data.get("root_mfa_enabled"),
                account_id,
                iam_data.get("error"),
            )
        )
        results.append(
            check_iam_root_access_keys(
                iam_data.get("root_access_keys_present"),
                account_id,
                iam_data.get("error"),
            )
        )

        # 2. CloudTrail Checks
        ct_data = self._fetch_cloudtrail_posture()
        results.append(
            check_cloudtrail_enabled(
                ct_data.get("trails"),
                account_id,
                ct_data.get("error"),
            )
        )

        # 3. S3 Bucket Checks
        for bucket in buckets:
            results.append(check_s3_public_access(bucket))
            results.append(check_s3_encryption(bucket))
            results.append(check_s3_versioning(bucket))

        # 4. Security Group Checks (deduplicated by group_id)
        seen_sgs = set()
        for sg in security_groups:
            if sg.group_id and sg.group_id not in seen_sgs:
                seen_sgs.add(sg.group_id)
                results.append(check_sg_ssh(sg))
                results.append(check_sg_rdp(sg))

        # 5. Compute Summary
        summary = self._compute_summary(results)
        return results, summary

    def _compute_summary(self, results: List[CISCheckResult]) -> CISSummary:
        total = len(results)
        passed = sum(1 for r in results if r.status == "PASS")
        failed = sum(1 for r in results if r.status == "FAIL")
        warnings = sum(1 for r in results if r.status == "WARNING")
        errors = sum(1 for r in results if r.status == "ERROR")
        unknowns = sum(1 for r in results if r.status == "UNKNOWN")

        crit_fails = sum(1 for r in results if r.status == "FAIL" and r.severity == "CRITICAL")
        high_fails = sum(1 for r in results if r.status == "FAIL" and r.severity == "HIGH")
        med_fails = sum(1 for r in results if r.status == "FAIL" and r.severity == "MEDIUM")
        low_fails = sum(1 for r in results if r.status == "FAIL" and r.severity == "LOW")

        # Compliance score: passed / total evaluated checks (excluding errors)
        evaluable_total = passed + failed + warnings
        score = round((passed / evaluable_total) * 100, 1) if evaluable_total > 0 else (100.0 if total > 0 and errors == 0 else 0.0)

        return CISSummary(
            total_checks=total,
            passed_checks=passed,
            failed_checks=failed,
            warning_checks=warnings,
            error_checks=errors,
            unknown_checks=unknowns,
            compliance_score_percent=score,
            critical_failures=crit_fails,
            high_failures=high_fails,
            medium_failures=med_fails,
            low_failures=low_fails,
        )


benchmark_engine = CISBenchmarkEngine()
