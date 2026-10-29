"""
Cloud Posture Scanner - FastAPI Backend Application.
Provides REST APIs for cloud resource discovery, CIS benchmark audits, and posture management.
Persists compliance scan artifacts exclusively to Amazon S3 or local development storage.
"""
import io
import csv
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pathlib import Path

from fastapi import FastAPI, Query, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse

from backend.config import settings, BASE_DIR
from backend.core.aws_client import aws_manager
from backend.discovery.ec2_discovery import discover_ec2_resources
from backend.discovery.s3_discovery import discover_s3_resources
from backend.benchmark.engine import benchmark_engine
from backend.storage.storage_service import storage_service
from backend.models.schemas import (
    EC2Instance,
    S3Bucket,
    CISCheckResult,
    CISSummary,
    ScanReport,
    ScanSummaryItem,
    AWSConfigPayload,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cloud_posture.api")

app = FastAPI(
    title="Cloud Posture Scanner API",
    description="Lightweight CSPM tool discovering AWS EC2 and S3 resources, executing CIS Benchmark checks, and persisting security audit reports.",
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory cache of latest scan & last successful scan time
_current_scan_report: Optional[ScanReport] = None
_last_successful_scan_time: Optional[str] = None


def run_full_scan(custom_s3_bucket: Optional[str] = None) -> ScanReport:
    """Executes a complete posture scan and stores results to S3 or local development store."""
    global _current_scan_report, _last_successful_scan_time
    scan_id = str(uuid.uuid4())[:8]
    start_time = datetime.now(timezone.utc).isoformat()
    mode = "DEMO_SIMULATION" if aws_manager.is_mock_mode() else "LIVE_AWS"
    account_id = aws_manager.get_account_id()

    logger.info(f"Starting cloud posture scan [{scan_id}] in {mode} mode for account {account_id}")

    # 1. Discover Resources and Capture Discovery Errors
    instances, all_sgs, ec2_errors = discover_ec2_resources(regions=settings.SCAN_REGIONS)
    buckets, s3_errors = discover_s3_resources()
    all_scan_errors = ec2_errors + s3_errors

    # 2. Run CIS Benchmark Checks
    cis_results, summary = benchmark_engine.run_all_checks(
        buckets=buckets,
        security_groups=all_sgs,
        instances=instances,
    )

    completion_time = datetime.now(timezone.utc).isoformat()
    scan_status = "PARTIAL" if all_scan_errors else "COMPLETED"

    # 3. Build Scan Report
    report_dict = {
        "scan_id": scan_id,
        "aws_account_id": account_id,
        "start_time": start_time,
        "completion_time": completion_time,
        "timestamp": completion_time,
        "status": scan_status,
        "mode": mode,
        "target_regions": settings.SCAN_REGIONS,
        "instances": [inst.model_dump() for inst in instances],
        "buckets": [b.model_dump() for b in buckets],
        "cis_results": [r.model_dump() for r in cis_results],
        "summary": summary.model_dump(),
        "scan_errors": all_scan_errors,
    }

    # 4. Store Report Securely in Amazon S3
    storage_meta = storage_service.save_report(
        report_data=report_dict,
        custom_s3_bucket=custom_s3_bucket,
    )

    report_dict["storage"] = storage_meta.model_dump()
    _current_scan_report = ScanReport(**report_dict)
    _last_successful_scan_time = completion_time

    logger.info(
        f"Scan [{scan_id}] completed ({scan_status}). Compliance Score: {summary.compliance_score_percent}%"
    )
    return _current_scan_report


def get_or_run_scan() -> ScanReport:
    """Returns the latest scan report or generates one automatically."""
    global _current_scan_report, _last_successful_scan_time
    if _current_scan_report is not None:
        return _current_scan_report

    # Attempt to load from storage
    latest_saved = storage_service.get_latest_report()
    if latest_saved:
        try:
            _current_scan_report = ScanReport(**latest_saved)
            _last_successful_scan_time = _current_scan_report.completion_time
            return _current_scan_report
        except Exception as e:
            logger.warning(f"Could not load saved report into model: {e}")

    # Otherwise execute an initial scan
    return run_full_scan()


# ==========================================================
# REST API Endpoints
# ==========================================================

@app.get("/health", tags=["System"])
@app.get("/api/v1/health", tags=["System"])
def health_check():
    """
    Returns API health status, AWS connectivity mode, connected account ID,
    configured regions, storage bucket, and last successful scan time.
    """
    is_connected, conn_msg, account_id = aws_manager.verify_credentials()
    mode = "DEMO_SIMULATION" if aws_manager.is_mock_mode() else "LIVE_AWS"
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "aws_connected": is_connected,
        "connection_message": conn_msg,
        "account_id": account_id or "123456789012",
        "active_profile": settings.AWS_PROFILE or None,
        "default_region": settings.AWS_DEFAULT_REGION,
        "scan_regions": settings.SCAN_REGIONS,
        "storage_bucket": settings.AWS_POSTURE_BUCKET or None,
        "last_successful_scan_time": _last_successful_scan_time,
        "version": settings.APP_VERSION,
    }


@app.post("/scan", response_model=ScanReport, tags=["Scanning"])
@app.post("/api/v1/scan", response_model=ScanReport, tags=["Scanning"])
def trigger_scan(
    s3_bucket: Optional[str] = Query(None, description="Optional target AWS S3 bucket to persist audit report"),
):
    """Triggers an on-demand cloud posture scan across EC2, S3, IAM, and Networking."""
    return run_full_scan(custom_s3_bucket=s3_bucket)


@app.get("/instances", response_model=List[EC2Instance], tags=["Discovery"])
@app.get("/api/v1/instances", response_model=List[EC2Instance], tags=["Discovery"])
def get_instances(
    region: Optional[str] = Query(None, description="Filter by AWS Region (e.g. us-east-1)"),
    state: Optional[str] = Query(None, description="Filter by instance state (running, stopped)"),
):
    """
    Lists discovered EC2 instances with:
    instance ID, name, type, region, public IP, state, and associated security groups.
    """
    report = get_or_run_scan()
    instances = report.instances

    if region:
        instances = [i for i in instances if i.region.lower() == region.lower()]
    if state:
        instances = [i for i in instances if i.state.lower() == state.lower()]

    return instances


@app.get("/buckets", response_model=List[S3Bucket], tags=["Discovery"])
@app.get("/api/v1/buckets", response_model=List[S3Bucket], tags=["Discovery"])
def get_buckets(
    access_policy: Optional[str] = Query(None, description="Filter by access policy: Public or Private"),
    encryption_status: Optional[str] = Query(None, description="Filter by encryption status"),
):
    """
    Lists discovered S3 buckets with:
    bucket name, region, encryption status, and access policy (public/private).
    """
    report = get_or_run_scan()
    buckets = report.buckets

    if access_policy:
        buckets = [b for b in buckets if b.access_policy.lower() == access_policy.lower()]
    if encryption_status:
        buckets = [b for b in buckets if encryption_status.lower() in b.encryption_status.lower()]

    return buckets


@app.get("/cis-results", response_model=List[CISCheckResult], tags=["CIS Benchmark"])
@app.get("/api/v1/cis-results", response_model=List[CISCheckResult], tags=["CIS Benchmark"])
def get_cis_results(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: PASS, FAIL, WARNING, ERROR, UNKNOWN"),
    category: Optional[str] = Query(None, description="Filter by category: S3, IAM, EC2 / Networking, Logging"),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
):
    """
    Returns CIS AWS Benchmark audit results with:
    check ID, title, status, severity, category, concrete evidence, and remediation steps.
    """
    report = get_or_run_scan()
    results = report.cis_results

    if status_filter:
        results = [r for r in results if r.status.upper() == status_filter.upper()]
    if category:
        results = [r for r in results if category.lower() in r.category.lower()]
    if severity:
        results = [r for r in results if r.severity.upper() == severity.upper()]

    return results


@app.get("/scans", response_model=List[ScanSummaryItem], tags=["Scanning"])
@app.get("/api/v1/scans", response_model=List[ScanSummaryItem], tags=["Scanning"])
def list_scans():
    """Returns historical scan reports / summaries retrieved from Amazon S3 or local storage."""
    history_items = storage_service.list_historical_scans()
    return [
        ScanSummaryItem(
            scan_id=item.get("scan_id", ""),
            timestamp=item.get("timestamp", ""),
            completion_time=item.get("completion_time"),
            aws_account_id=item.get("aws_account_id"),
            mode=item.get("mode", "UNKNOWN"),
            status=item.get("status", "COMPLETED"),
            compliance_score=float(item.get("compliance_score", 0.0) or 0.0),
            total_checks=int(item.get("total_checks", 0) or 0),
            passed_checks=int(item.get("passed_checks", 0) or 0),
            failed_checks=int(item.get("failed_checks", 0) or 0),
            error_checks=int(item.get("error_checks", 0) or 0),
            instances_count=int(item.get("instances_count", 0) or 0),
            buckets_count=int(item.get("buckets_count", 0) or 0),
            storage_destination=item.get("storage_destination", "Local-Storage"),
            storage_location=item.get("storage_location", ""),
        )
        for item in history_items
    ]


@app.get("/scans/{scan_id}", response_model=ScanReport, tags=["Scanning"])
@app.get("/api/v1/scans/{scan_id}", response_model=ScanReport, tags=["Scanning"])
def get_scan_by_id(scan_id: str):
    """Retrieves a specific scan report by its scan ID from Amazon S3 or local storage."""
    global _current_scan_report
    if _current_scan_report and _current_scan_report.scan_id == scan_id:
        return _current_scan_report

    report_dict = storage_service.get_report_by_id(scan_id)
    if not report_dict:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan report with ID '{scan_id}' not found.",
        )
    return ScanReport(**report_dict)


@app.get("/summary", response_model=CISSummary, tags=["CIS Benchmark"])
@app.get("/api/v1/summary", response_model=CISSummary, tags=["CIS Benchmark"])
def get_summary():
    """Returns high-level posture compliance summary, score percentage, and failure metrics."""
    report = get_or_run_scan()
    return report.summary


@app.get("/report/latest", response_model=ScanReport, tags=["Scanning"])
@app.get("/api/v1/report/latest", response_model=ScanReport, tags=["Scanning"])
def get_latest_report():
    """Returns the full latest posture report including instances, buckets, CIS checks, and storage metadata."""
    return get_or_run_scan()


@app.get("/history", tags=["Scanning"])
@app.get("/api/v1/history", tags=["Scanning"])
def get_scan_history():
    """Alias for /scans to maintain dashboard backwards compatibility."""
    return storage_service.list_historical_scans()


@app.post("/configure", tags=["Configuration"])
@app.post("/api/v1/configure", tags=["Configuration"])
def configure_aws(payload: AWSConfigPayload):
    """
    Configures AWS CLI profile, default region, scan regions, or S3 bucket at runtime.
    Does NOT accept permanent secrets; uses standard AWS credential provider chain.
    """
    if payload.aws_profile is not None:
        settings.AWS_PROFILE = payload.aws_profile
    if payload.aws_region:
        settings.AWS_DEFAULT_REGION = payload.aws_region
    if payload.scan_regions:
        settings.SCAN_REGIONS = payload.scan_regions
    if payload.s3_storage_bucket is not None:
        settings.AWS_POSTURE_BUCKET = payload.s3_storage_bucket
    if payload.use_mock is not None:
        settings.USE_MOCK = payload.use_mock
        aws_manager.force_mock_mode(payload.use_mock)

    aws_manager.reset_session()
    connected, msg, account_id = aws_manager.verify_credentials(force_refresh=True)
    mode = "DEMO_SIMULATION" if aws_manager.is_mock_mode() else "LIVE_AWS"

    # Invalidate cache so next request fetches fresh data with new configuration
    global _current_scan_report
    _current_scan_report = None

    return {
        "status": "configured",
        "mode": mode,
        "connected": connected,
        "message": msg,
        "account_id": account_id or "123456789012",
        "active_profile": settings.AWS_PROFILE or None,
        "default_region": settings.AWS_DEFAULT_REGION,
        "scan_regions": settings.SCAN_REGIONS,
        "storage_bucket": settings.AWS_POSTURE_BUCKET or None,
    }


@app.get("/export/csv", tags=["Export"])
@app.get("/api/v1/export/csv", tags=["Export"])
def export_csv(resource_type: str = Query("cis", description="Type: cis, instances, or buckets")):
    """Exports findings to CSV format."""
    report = get_or_run_scan()
    output = io.StringIO()

    if resource_type.lower() == "instances":
        writer = csv.writer(output)
        writer.writerow(["InstanceID", "Name", "Type", "Region", "State", "PublicIP", "PrivateIP", "VPC", "SecurityGroups"])
        for inst in report.instances:
            sg_names = ", ".join([sg.group_name for sg in inst.security_groups])
            writer.writerow([inst.instance_id, inst.name, inst.instance_type, inst.region, inst.state, inst.public_ip or "None", inst.private_ip or "None", inst.vpc_id or "None", sg_names])
        filename = f"ec2_instances_{report.scan_id}.csv"

    elif resource_type.lower() == "buckets":
        writer = csv.writer(output)
        writer.writerow(["BucketName", "Region", "Encryption", "AccessPolicy", "BlockPublicAcls", "BlockPublicPolicy", "Versioning"])
        for b in report.buckets:
            writer.writerow([
                b.bucket_name,
                b.region,
                b.encryption_status,
                b.access_policy,
                b.public_access_block.block_public_acls,
                b.public_access_block.block_public_policy,
                b.versioning_status,
            ])
        filename = f"s3_buckets_{report.scan_id}.csv"

    else:
        writer = csv.writer(output)
        writer.writerow(["CheckID", "Title", "Category", "Severity", "Status", "ResourceID", "ResourceType", "Evidence", "Remediation"])
        for r in report.cis_results:
            writer.writerow([r.check_id, r.title, r.category, r.severity, r.status, r.resource_id, r.resource_type, r.evidence, r.remediation])
        filename = f"cis_benchmark_results_{report.scan_id}.csv"

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ==========================================================
# Frontend Dashboard Static Files Mount
# ==========================================================
frontend_dir = BASE_DIR / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/", include_in_schema=False)
    def serve_frontend_dashboard():
        return FileResponse(str(frontend_dir / "index.html"))
