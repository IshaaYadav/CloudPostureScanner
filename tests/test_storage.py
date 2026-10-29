"""
Tests for Secure Amazon S3 Storage Service.
Verifies S3 uploads, retrievals, scan history, upload failures, and JSON serialization.
"""
import io
import json
from datetime import datetime, date, timezone
from decimal import Decimal
from unittest.mock import MagicMock, patch
import pytest
from botocore.exceptions import ClientError

from backend.config import settings
from backend.core.aws_client import aws_manager
from backend.storage.storage_service import (
    storage_service,
    safe_json_serializer,
    dumps_safe_json,
)
from backend.models.schemas import StorageMetadata


@pytest.fixture
def sample_report_data():
    return {
        "scan_id": "test-s3-scan-01",
        "aws_account_id": "112233445566",
        "start_time": "2026-10-30T00:00:00+00:00",
        "completion_time": "2026-10-30T00:01:00+00:00",
        "timestamp": "2026-10-30T00:01:00+00:00",
        "status": "COMPLETED",
        "mode": "LIVE_AWS",
        "target_regions": ["ap-south-1"],
        "instances": [],
        "buckets": [],
        "cis_results": [],
        "summary": {
            "total_checks": 5,
            "passed_checks": 4,
            "failed_checks": 1,
            "compliance_score_percent": 80.0,
            "critical_failures": 1,
            "high_failures": 0,
        },
        "scan_errors": [],
    }


def test_safe_json_serializer():
    """Verifies that dates, Decimals, and sets serialize without exceptions."""
    payload = {
        "datetime_val": datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc),
        "date_val": date(2026, 10, 30),
        "decimal_val": Decimal("49.99"),
        "set_val": {"region-b", "region-a"},
    }
    json_str = dumps_safe_json(payload)
    parsed = json.loads(json_str)

    assert parsed["datetime_val"] == "2026-10-30T12:00:00+00:00"
    assert parsed["date_val"] == "2026-10-30"
    assert parsed["decimal_val"] == 49.99
    assert parsed["set_val"] == ["region-a", "region-b"]


def test_storage_local_save_and_retrieve(sample_report_data):
    """Verifies fallback to local storage when S3 bucket is not configured or in mock mode."""
    aws_manager.force_mock_mode(True)
    meta = storage_service.save_report(sample_report_data)

    assert meta.status == "SUCCESS"
    assert meta.destination == "Local-Storage"
    assert "scan_test-s3-scan-01" in meta.location

    # Retrieve by scan ID
    retrieved = storage_service.get_report_by_id("test-s3-scan-01")
    assert retrieved is not None
    assert retrieved["scan_id"] == "test-s3-scan-01"
    assert retrieved["aws_account_id"] == "112233445566"


def test_s3_upload_success(sample_report_data):
    """Verifies that scans are uploaded to S3 with key scans/YYYY/MM/DD/<scan_id>.json and AES256."""
    mock_s3 = MagicMock()
    
    with patch.object(aws_manager, "is_mock_mode", return_value=False), \
         patch.object(aws_manager, "get_client", return_value=mock_s3):

        meta = storage_service.save_report(
            sample_report_data,
            custom_s3_bucket="my-private-posture-bucket",
        )

        assert meta.status == "SUCCESS"
        assert meta.destination == "AWS-S3"
        assert meta.location.startswith("s3://my-private-posture-bucket/scans/2026/10/30/test-s3-scan-01.json")
        assert meta.encrypted is True

        # Verify put_object was called with required SSE-S3 encryption
        mock_s3.put_object.assert_called_once()
        call_kwargs = mock_s3.put_object.call_args[1]
        assert call_kwargs["Bucket"] == "my-private-posture-bucket"
        assert call_kwargs["Key"] == "scans/2026/10/30/test-s3-scan-01.json"
        assert call_kwargs["ServerSideEncryption"] == "AES256"
        assert call_kwargs["ContentType"] == "application/json"


def test_s3_upload_failure_explicit(sample_report_data):
    """Verifies that an S3 upload failure returns an explicit failure, not a masked success."""
    mock_s3 = MagicMock()
    mock_s3.put_object.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access Denied to S3 bucket"}},
        "PutObject",
    )

    with patch.object(aws_manager, "is_mock_mode", return_value=False), \
         patch.object(aws_manager, "get_client", return_value=mock_s3):

        meta = storage_service.save_report(
            sample_report_data,
            custom_s3_bucket="restricted-posture-bucket",
        )

        assert meta.status == "FAILED"
        assert meta.destination == "AWS-S3"
        assert "AccessDenied" in meta.error_message


def test_s3_get_report_by_id(sample_report_data, monkeypatch):
    """Verifies retrieving a scan report directly from S3 bucket."""
    mock_s3 = MagicMock()
    
    # Mock paginator for list_objects_v2
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"Contents": [{"Key": "scans/2026/10/30/test-s3-scan-01.json"}]}
    ]
    mock_s3.get_paginator.return_value = paginator

    # Mock get_object response
    body_mock = MagicMock()
    body_mock.read.return_value = dumps_safe_json(sample_report_data).encode("utf-8")
    mock_s3.get_object.return_value = {"Body": body_mock}

    monkeypatch.setattr(settings, "AWS_POSTURE_BUCKET", "test-bucket")

    with patch.object(aws_manager, "is_mock_mode", return_value=False), \
         patch.object(aws_manager, "get_client", return_value=mock_s3):

        report = storage_service.get_report_by_id("test-s3-scan-01")
        assert report is not None
        assert report["scan_id"] == "test-s3-scan-01"
        assert report["aws_account_id"] == "112233445566"


def test_s3_list_historical_scans(sample_report_data, monkeypatch):
    """Verifies listing scan summaries from S3 bucket."""
    mock_s3 = MagicMock()
    mock_s3.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": "scans/2026/10/30/test-s3-scan-01.json",
                "LastModified": datetime(2026, 10, 30, 0, 1, 0, tzinfo=timezone.utc),
            }
        ]
    }
    body_mock = MagicMock()
    body_mock.read.return_value = dumps_safe_json(sample_report_data).encode("utf-8")
    mock_s3.get_object.return_value = {"Body": body_mock}

    monkeypatch.setattr(settings, "AWS_POSTURE_BUCKET", "test-bucket")

    with patch.object(aws_manager, "is_mock_mode", return_value=False), \
         patch.object(aws_manager, "get_client", return_value=mock_s3):

        history = storage_service.list_historical_scans()
        assert len(history) >= 1
        first = history[0]
        assert first["scan_id"] == "test-s3-scan-01"
        assert first["storage_destination"] == "AWS-S3"
        assert first["compliance_score"] == 80.0
