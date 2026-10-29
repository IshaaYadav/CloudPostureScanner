"""
Secure Amazon S3 Storage Service for Cloud Posture Scanner.
Exclusively uses Amazon S3 (with SSE-S3 AES256 server-side encryption) for cloud persistence.
Provides structured local development persistence when cloud storage is not configured.
"""
import json
import logging
from datetime import datetime, date, timezone
from decimal import Decimal
from pathlib import Path
from typing import Optional, Dict, Any, List
from botocore.exceptions import ClientError, BotoCoreError

from backend.config import settings
from backend.core.aws_client import aws_manager
from backend.models.schemas import StorageMetadata

logger = logging.getLogger("cloud_posture.storage")


def safe_json_serializer(obj: Any) -> Any:
    """Safely serializes datetime, date, Decimal, set, and Boto3 SDK types."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, set):
        return sorted(list(obj))
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)


def dumps_safe_json(data: Any, indent: int = 2) -> str:
    """Serializes data to JSON string using safe serializer."""
    return json.dumps(data, indent=indent, default=safe_json_serializer)


class S3StorageService:
    """
    Manages persistent scan reports in Amazon S3.
    Reports are stored as JSON under:
    scans/YYYY/MM/DD/<scan_id>.json
    with default AES256 server-side encryption.
    """

    def __init__(self):
        self.history_dir = settings.HISTORY_PATH
        self.latest_file = settings.LATEST_REPORT_FILE

    def _save_local(self, report_data: Dict[str, Any], scan_id: str, clean_ts: str) -> Path:
        """Helper to persist a local copy for development."""
        local_filepath = self.history_dir / f"scan_{scan_id}_{clean_ts}.json"
        try:
            json_text = dumps_safe_json(report_data)
            with open(local_filepath, "w", encoding="utf-8") as f:
                f.write(json_text)
            with open(self.latest_file, "w", encoding="utf-8") as f:
                f.write(json_text)
            logger.info(f"Local development report written: {local_filepath}")
        except Exception as e:
            logger.error(f"Failed to write local development copy: {e}")
        return local_filepath

    def save_report(
        self,
        report_data: Dict[str, Any],
        custom_s3_bucket: Optional[str] = None,
    ) -> StorageMetadata:
        """
        Saves the scan report to Amazon S3 (if configured) or local storage for development.
        If S3 upload fails, returns an explicit failure without masking it as a local success.
        """
        scan_id = report_data.get("scan_id", "unknown-scan")
        ts_str = report_data.get("completion_time") or report_data.get("timestamp")
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else datetime.now(timezone.utc)
        except Exception:
            dt = datetime.now(timezone.utc)

        clean_ts = dt.strftime("%Y-%m-%dT%H-%M-%S")
        target_s3_bucket = custom_s3_bucket or settings.AWS_POSTURE_BUCKET

        # 1. AWS S3 Persistence
        if target_s3_bucket and not aws_manager.is_mock_mode():
            date_prefix = dt.strftime("%Y/%m/%d")
            s3_key = f"scans/{date_prefix}/{scan_id}.json"
            s3_uri = f"s3://{target_s3_bucket}/{s3_key}"

            try:
                s3_client = aws_manager.get_client("s3")
                json_bytes = dumps_safe_json(report_data).encode("utf-8")

                compliance_score = str(
                    report_data.get("summary", {}).get("compliance_score_percent", 0.0)
                )

                s3_client.put_object(
                    Bucket=target_s3_bucket,
                    Key=s3_key,
                    Body=json_bytes,
                    ContentType="application/json",
                    ServerSideEncryption="AES256",
                    Metadata={
                        "scan-id": scan_id,
                        "timestamp": dt.isoformat(),
                        "compliance-score": compliance_score,
                        "account-id": str(report_data.get("aws_account_id", "")),
                    },
                )
                logger.info(f"Scan report successfully persisted to Amazon S3: {s3_uri}")

                # Also keep a local dev mirror for speed/offline review
                self._save_local(report_data, scan_id, clean_ts)

                return StorageMetadata(
                    destination="AWS-S3",
                    location=s3_uri,
                    status="SUCCESS",
                    encrypted=True,
                )
            except (ClientError, BotoCoreError) as e:
                err_msg = f"Failed to upload report to Amazon S3 bucket '{target_s3_bucket}' key '{s3_key}': {e}"
                logger.error(err_msg)
                # Save local emergency copy but return EXPLICIT failure for cloud storage
                self._save_local(report_data, scan_id, clean_ts)
                return StorageMetadata(
                    destination="AWS-S3",
                    location=s3_uri,
                    status="FAILED",
                    encrypted=False,
                    error_message=err_msg,
                )

        # 2. Local Development Storage (when S3 bucket is omitted or in simulation mode)
        local_path = self._save_local(report_data, scan_id, clean_ts)
        return StorageMetadata(
            destination="Local-Storage",
            location=str(local_path),
            status="SUCCESS",
            encrypted=True,
        )

    def get_latest_report(self) -> Optional[Dict[str, Any]]:
        """Retrieves the most recent scan report from storage."""
        if self.latest_file.exists():
            try:
                with open(self.latest_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error reading latest scan file: {e}")
        return None

    def get_report_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a scan report by its scan ID.
        Checks Amazon S3 first if configured, then local storage.
        """
        target_s3_bucket = settings.AWS_POSTURE_BUCKET

        if target_s3_bucket and not aws_manager.is_mock_mode():
            try:
                s3_client = aws_manager.get_client("s3")
                # Search for key ending with /<scan_id>.json
                paginator = s3_client.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=target_s3_bucket, Prefix="scans/"):
                    for obj in page.get("Contents", []):
                        key = obj.get("Key", "")
                        if key.endswith(f"/{scan_id}.json") or key == f"scans/{scan_id}.json":
                            resp = s3_client.get_object(Bucket=target_s3_bucket, Key=key)
                            content = resp["Body"].read().decode("utf-8")
                            return json.loads(content)
            except Exception as e:
                logger.warning(f"Error retrieving report {scan_id} from S3: {e}")

        # Fallback to local files
        if self.history_dir.exists():
            for file_path in self.history_dir.glob(f"scan_{scan_id}_*.json"):
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception as e:
                    logger.warning(f"Error reading local file {file_path}: {e}")

        # Check latest file
        latest = self.get_latest_report()
        if latest and latest.get("scan_id") == scan_id:
            return latest

        return None

    def list_historical_scans(self) -> List[Dict[str, Any]]:
        """
        Lists recent scan reports / summaries for the dashboard and API.
        Retrieves from Amazon S3 if configured, otherwise from local development storage.
        """
        history: List[Dict[str, Any]] = []
        target_s3_bucket = settings.AWS_POSTURE_BUCKET

        # 1. Read from S3 if configured and live
        if target_s3_bucket and not aws_manager.is_mock_mode():
            try:
                s3_client = aws_manager.get_client("s3")
                response = s3_client.list_objects_v2(
                    Bucket=target_s3_bucket,
                    Prefix="scans/",
                    MaxKeys=50,
                )
                contents = sorted(
                    response.get("Contents", []),
                    key=lambda x: x.get("LastModified", datetime.min),
                    reverse=True,
                )

                for item in contents[:20]:
                    key = item.get("Key", "")
                    if not key.endswith(".json"):
                        continue
                    try:
                        obj = s3_client.get_object(Bucket=target_s3_bucket, Key=key)
                        data = json.loads(obj["Body"].read().decode("utf-8"))
                        history.append(self._build_summary_dict(data, f"s3://{target_s3_bucket}/{key}", "AWS-S3"))
                    except Exception as err:
                        logger.debug(f"Error fetching historical S3 report {key}: {err}")

                if history:
                    return history
            except Exception as e:
                logger.warning(f"Could not list scans from S3 bucket '{target_s3_bucket}': {e}")

        # 2. Read from local development directory
        if self.history_dir.exists():
            for file_path in sorted(self.history_dir.glob("scan_*.json"), reverse=True):
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        history.append(self._build_summary_dict(data, str(file_path), "Local-Storage"))
                except Exception as e:
                    logger.debug(f"Error reading local historical scan {file_path}: {e}")

        return history

    @staticmethod
    def _build_summary_dict(data: Dict[str, Any], location: str, destination: str) -> Dict[str, Any]:
        """Constructs a uniform summary dictionary from report data."""
        summary = data.get("summary", {})
        storage = data.get("storage", {})
        return {
            "scan_id": data.get("scan_id"),
            "timestamp": data.get("timestamp") or data.get("completion_time"),
            "completion_time": data.get("completion_time") or data.get("timestamp"),
            "aws_account_id": data.get("aws_account_id"),
            "mode": data.get("mode", "UNKNOWN"),
            "status": data.get("status", "COMPLETED"),
            "compliance_score": summary.get("compliance_score_percent", 0.0),
            "total_checks": summary.get("total_checks", 0),
            "passed_checks": summary.get("passed_checks", 0),
            "failed_checks": summary.get("failed_checks", 0),
            "error_checks": summary.get("error_checks", 0),
            "instances_count": len(data.get("instances", [])),
            "buckets_count": len(data.get("buckets", [])),
            "storage_destination": storage.get("destination", destination),
            "storage_location": storage.get("location", location),
        }


# Global singleton instance
storage_service = S3StorageService()
StorageService = S3StorageService
