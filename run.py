"""
Entry point launcher for Cloud Posture Scanner.
Starts the FastAPI application and REST endpoints.
"""
import sys
import logging
import uvicorn
from backend.config import settings
from backend.core.aws_client import aws_manager


def main():
    print("=" * 72)
    print("  🛡️   CLOUD POSTURE SCANNER v1.0.0")
    print("  AWS Multi-Region Discovery & CIS Foundations Benchmark Engine")
    print("=" * 72)

    # Check initial AWS connectivity
    connected, msg, account_id = aws_manager.verify_credentials()
    if connected:
        print(f"  [✓] AWS Status:      LIVE CONNECTED (Account: {account_id})")
        if settings.AWS_PROFILE:
            print(f"  [✓] CLI Profile:     {settings.AWS_PROFILE}")
        print(f"  [✓] Default Region:  {settings.AWS_DEFAULT_REGION}")
        print(f"  [✓] Scan Regions:    {', '.join(settings.SCAN_REGIONS)}")
        if settings.AWS_POSTURE_BUCKET:
            print(f"  [✓] S3 Report Vault: s3://{settings.AWS_POSTURE_BUCKET}/scans/")
        else:
            print(f"  [i] S3 Report Vault: Not configured (using Local-Storage data/history/)")
    else:
        print(f"  [!] AWS Status:      Simulation / Mock Mode Active")
        print(f"      Details: {msg}")
        print(f"      (To connect live AWS credentials, configure a named profile or .env)")

    print("-" * 72)
    print(f"  🚀 Web Dashboard:        http://localhost:{settings.PORT}/")
    print(f"  📚 Interactive API Docs:  http://localhost:{settings.PORT}/docs")
    print(f"  🔍 Core REST Endpoints:  /instances, /buckets, /cis-results, /scans")
    print("=" * 72)

    uvicorn.run(
        "backend.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
