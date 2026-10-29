"""
Tests for FastAPI REST API Endpoints.
Verifies all required assignment endpoints, schemas, filtering, and error handling.
"""
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.core.aws_client import aws_manager
from backend.config import settings

client = TestClient(app)


@pytest.fixture(autouse=True)
def ensure_mock_mode():
    aws_manager.force_mock_mode(True)


def test_health_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "mode" in data
    assert "account_id" in data
    assert "default_region" in data
    assert "scan_regions" in data


def test_trigger_scan_endpoint():
    res = client.post("/scan")
    assert res.status_code == 200
    data = res.json()
    assert "scan_id" in data
    assert "aws_account_id" in data
    assert "start_time" in data
    assert "completion_time" in data
    assert "status" in data
    assert "instances" in data
    assert "buckets" in data
    assert "cis_results" in data
    assert "summary" in data
    assert "storage" in data


def test_get_instances_endpoint_and_filters():
    res = client.get("/instances")
    assert res.status_code == 200
    instances = res.json()
    assert isinstance(instances, list)
    assert len(instances) > 0
    first = instances[0]
    assert "instance_id" in first
    assert "instance_type" in first
    assert "region" in first
    assert "security_groups" in first

    # Test filtering by region
    res_filtered = client.get("/instances?region=us-east-1")
    assert res_filtered.status_code == 200
    assert all(i["region"] == "us-east-1" for i in res_filtered.json())

    # Test filtering by state
    res_state = client.get("/instances?state=running")
    assert res_state.status_code == 200
    assert all(i["state"] == "running" for i in res_state.json())


def test_get_buckets_endpoint_and_filters():
    res = client.get("/buckets")
    assert res.status_code == 200
    buckets = res.json()
    assert isinstance(buckets, list)
    assert len(buckets) > 0
    first = buckets[0]
    assert "bucket_name" in first
    assert "encryption_status" in first
    assert "access_policy" in first

    # Filter by access policy
    res_pub = client.get("/buckets?access_policy=Public")
    assert res_pub.status_code == 200
    assert all(b["access_policy"] == "Public" for b in res_pub.json())


def test_get_cis_results_endpoint_and_filters():
    res = client.get("/cis-results")
    assert res.status_code == 200
    results = res.json()
    assert isinstance(results, list)
    assert len(results) >= 5  # At least 5 CIS checks required
    first = results[0]
    assert "check_id" in first
    assert "title" in first
    assert "status" in first
    assert "severity" in first
    assert "evidence" in first
    assert "remediation" in first

    # Filter by status
    res_fail = client.get("/cis-results?status=FAIL")
    assert res_fail.status_code == 200
    assert all(r["status"] == "FAIL" for r in res_fail.json())

    # Filter by category
    res_cat = client.get("/cis-results?category=S3")
    assert res_cat.status_code == 200
    assert all("S3" in r["category"] for r in res_cat.json())


def test_get_scans_and_get_scan_by_id():
    # 1. Trigger a scan first
    scan_res = client.post("/scan")
    assert scan_res.status_code == 200
    scan_id = scan_res.json()["scan_id"]

    # 2. List scans
    scans_res = client.get("/scans")
    assert scans_res.status_code == 200
    scans_list = scans_res.json()
    assert isinstance(scans_list, list)
    assert any(s["scan_id"] == scan_id for s in scans_list)

    # 3. Get scan by ID
    get_res = client.get(f"/scans/{scan_id}")
    assert get_res.status_code == 200
    assert get_res.json()["scan_id"] == scan_id

    # 4. Get nonexistent scan should return 404
    missing_res = client.get("/scans/non-existent-scan-id-999")
    assert missing_res.status_code == 404


def test_get_summary_endpoint():
    res = client.get("/summary")
    assert res.status_code == 200
    summary = res.json()
    assert "compliance_score_percent" in summary
    assert "total_checks" in summary
    assert "passed_checks" in summary
    assert "failed_checks" in summary


def test_export_csv_endpoint():
    res = client.get("/export/csv?resource_type=cis")
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]
    assert "CheckID" in res.text


def test_configure_endpoint_safe():
    payload = {
        "aws_region": "ap-south-1",
        "scan_regions": ["ap-south-1"],
        "use_mock": True,
    }
    res = client.post("/configure", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "configured"
    assert data["default_region"] == "ap-south-1"


def test_no_credentials_leaked_in_responses():
    """Verifies that no AWS secrets, keys, or tokens appear in health or scan responses."""
    health_res = client.get("/health")
    health_text = health_res.text.lower()
    assert "aws_secret_access_key" not in health_text
    assert "secret" not in health_text or "token" not in health_text

    scan_res = client.post("/scan")
    scan_text = scan_res.text
    assert "aws_secret_access_key" not in scan_text
    assert "aws_session_token" not in scan_text
    assert "AKIA" not in scan_text


def test_simulation_vs_live_mode_representation():
    """Verifies clear separation of simulation vs live modes in health endpoint."""
    aws_manager.force_mock_mode(True)
    res_mock = client.get("/health")
    assert res_mock.json()["mode"] == "DEMO_SIMULATION"
    assert res_mock.json()["aws_connected"] is False

    with patch.object(aws_manager, "verify_credentials", return_value=(True, "Connected as arn:aws:iam::999888777666:user/tester", "999888777666")), \
         patch.object(aws_manager, "is_mock_mode", return_value=False):
        res_live = client.get("/health")
        assert res_live.json()["mode"] == "LIVE_AWS"
        assert res_live.json()["aws_connected"] is True
        assert res_live.json()["account_id"] == "999888777666"
