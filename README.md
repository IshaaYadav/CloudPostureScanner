# 🛡️ Cloud Posture Scanner

A lightweight, production-grade **Cloud Security Posture Management (CSPM)** scanner built with **FastAPI**, **Boto3**, and a modern **Tailwind CSS + Chart.js** dashboard. It connects to Amazon Web Services (AWS) using least-privilege read permissions, performs automated discovery across multi-region EC2 instances and S3 buckets, evaluates infrastructure against the **CIS AWS Foundations Benchmark**, and persists audit reports to a private **Amazon S3** bucket (with SSE-S3 AES256 encryption) or local structured development storage.

---

## 1. Project Overview and Problem Statement

Cloud misconfigurations—such as publicly accessible S3 storage buckets, unencrypted assets at rest, unmonitored regions, and unrestricted management port exposure (SSH/RDP)—remain the leading cause of security breaches in AWS environments.

**Cloud Posture Scanner** addresses this problem by providing an automated, developer-friendly CSPM engine that:
1. Discovers compute and storage assets across configured AWS regions without requiring third-party SaaS agents.
2. Validates security controls using evidence-backed rules aligned with authoritative CIS benchmarks.
3. Securely archives audit artifacts into a dedicated private Amazon S3 bucket with strict server-side encryption.
4. Provides dual-mode operation: **Live AWS Mode** for real accounts and **Simulation Mode** for safe offline demonstrations, local development, and CI/CD pipelines without incurring cloud costs.

---

## 2. Key Features

- **Multi-Region EC2 & Security Group Discovery:** Discovers instances, instance types, public/private IPs, operational states, and deeply inspects attached security groups for unrestricted inbound CIDRs (`0.0.0.0/0` and `::/0`).
- **S3 Bucket Configuration Audit:** Evaluates bucket region, default server-side encryption (`SSE-S3 AES256`, `SSE-KMS`, `Unencrypted`), public access policies, ACL grants, and four-point S3 Public Access Block (PAB) settings.
- **CIS AWS Foundations Benchmark Engine:** Evaluates core security controls with concrete technical evidence and actionable remediation commands.
- **Amazon S3-Only Cloud Persistence:** Exclusively uses Amazon S3 for cloud report archiving using timestamped object keys (`scans/YYYY/MM/DD/<scan_id>.json`) with default `AES256` encryption.
- **Transparent Storage Reliability:** Clearly distinguishes cloud S3 storage from local development storage; reports explicit failures if S3 uploads fail without silently masking errors.
- **Zero-Secret Security Architecture:** Uses the standard Boto3 credential provider chain and named AWS CLI profiles (`AWS_PROFILE`). Never asks users to enter permanent access keys into the web UI or API responses.
- **Single-Page Reactive Dashboard:** Built-in web interface featuring compliance score gauges, pass/fail/error status filters, one-click AWS CLI remediation copying, and S3 scan history.
- **Automated REST APIs & OpenAPI:** Fully documented Swagger/ReDoc endpoints for scanning, resource discovery, CIS results, and historical reports.

---

## 3. Architecture

```mermaid
flowchart TD
    User([Security Engineer / DevSecOps]) -->|Browser UI / HTTP| WebUI["Web Dashboard (Tailwind CSS + Chart.js)"]
    WebUI -->|REST API| API["FastAPI Application (Port 8000)"]
    
    subgraph ScannerCore ["Cloud Posture Scanner Core"]
        API --> Auth["AWS Client Manager (STS Identity & Profiles)"]
        API --> DiscEC2["EC2 & Security Group Discovery"]
        API --> DiscS3["S3 Bucket Discovery & Encryption Auditor"]
        
        DiscEC2 --> Benchmark["CIS Benchmark Engine (Rules Evaluation)"]
        DiscS3 --> Benchmark
        
        Benchmark --> Storage["S3 Storage Service (Safe JSON Serializer)"]
    end
    
    subgraph TargetAWS ["Target AWS Account"]
        Auth -.->|sts:GetCallerIdentity| STS["AWS STS"]
        DiscEC2 -.->|ec2:DescribeInstances| EC2["Amazon EC2 & Security Groups"]
        DiscS3 -.->|s3:ListAllMyBuckets / s3:Get*| S3["Amazon S3 Buckets"]
        Storage -->|s3:PutObject (AES256 Encrypted)| S3Vault["Private Audit Bucket (scans/YYYY/MM/DD/*.json)"]
    end
    
    subgraph LocalDev ["Offline / Local Development Mode"]
        DiscEC2 -.-> MockEC2["Simulated EC2 Inventory"]
        DiscS3 -.-> MockS3["Simulated S3 Inventory"]
        Storage --> LocalDisk["Local Development Disk (data/history/)"]
    end
```

---

## 4. Technology Stack

- **Backend Framework:** Python 3.10+ / [FastAPI](https://fastapi.tiangolo.com/) (Async ASGI REST API)
- **ASGI Server:** [Uvicorn](https://www.uvicorn.org/)
- **AWS SDK:** [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) & [Botocore](https://botocore.amazonaws.com/v1/documentation/api/latest/index.html)
- **Data Validation & Schemas:** [Pydantic v2](https://docs.pydantic.dev/)
- **Frontend Presentation:** HTML5, [Tailwind CSS](https://tailwindcss.com/) (CDN), [Lucide Icons](https://lucide.dev/), and [Chart.js](https://www.chartjs.org/)
- **Testing Suite:** [Pytest](https://docs.pytest.org/), [HTTPX](https://www.python-httpx.org/), and `unittest.mock`
- **Containerization:** Docker & Docker Compose

---

## 5. Repository Structure

```text
CloudPosture/
├── backend/
│   ├── benchmark/
│   │   ├── __init__.py          # Benchmark exports
│   │   ├── engine.py            # CIS evaluation engine & score computation
│   │   └── rules.py             # CIS rules (S3, IAM, CloudTrail, EC2 SG)
│   ├── core/
│   │   ├── __init__.py          # Core client exports
│   │   └── aws_client.py        # Boto3 session & STS credential verification
│   ├── discovery/
│   │   ├── __init__.py          # Discovery exports
│   │   ├── ec2_discovery.py     # Multi-region EC2 & SG discovery
│   │   └── s3_discovery.py      # S3 bucket, encryption, and public access evaluation
│   ├── models/
│   │   ├── __init__.py          # Model exports
│   │   └── schemas.py           # Pydantic schemas (EC2, S3, CIS, ScanReport)
│   ├── storage/
│   │   ├── __init__.py          # Storage exports
│   │   └── storage_service.py   # S3 storage service & local fallback
│   ├── config.py                # Centralized settings & environment loader
│   ├── main.py                  # FastAPI application & REST route handlers
│   └── mock_data.py             # Realistic offline simulation datasets
├── frontend/
│   ├── css/
│   │   └── styles.css           # Custom presentation styles
│   ├── js/
│   │   └── app.js               # Reactive dashboard controller
│   └── index.html               # Web dashboard UI
├── data/
│   └── history/
│       └── .gitkeep             # Runtime local scan storage directory
├── sample_reports/
│   └── sample_scan.json         # Reference schema scan artifact
├── tests/
│   ├── __init__.py
│   ├── test_api.py              # FastAPI endpoint tests & filter tests
│   ├── test_cis_benchmark.py    # Rule evaluation tests (Pass/Fail/Error)
│   ├── test_discovery.py        # EC2 and S3 discovery tests
│   └── test_storage.py          # S3 upload, retrieval, and failure tests
├── .env.example                 # Sanitized configuration template
├── .gitignore                   # Git exclusion configuration
├── docker-compose.yml           # Multi-container orchestration
├── Dockerfile                   # Minimal Python container build
├── README.md                    # Project documentation
├── requirements.txt             # Python dependencies
└── run.py                       # CLI application entry point
```

---

## 6. Prerequisites

- **Python:** 3.10, 3.11, 3.12, or 3.13 installed
- **AWS CLI:** Version 2.x configured (`aws --version`)
- **AWS Account:** (Optional for live scanning; offline simulation mode is active by default if credentials are not supplied)
- **Docker:** (Optional, for containerized execution)

---

## 7. Local Installation and Startup Instructions

### Step 1: Clone and Navigate
```bash
git clone https://github.com/<your-username>/CloudPosture.git
cd CloudPosture
```

### Step 2: Create and Activate Virtual Environment
On Linux/macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```
On Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run the Application
```bash
python run.py
```
Output will display the active connection mode and local URLs:
- **Web Dashboard:** [http://localhost:8000/](http://localhost:8000/)
- **Interactive Swagger Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc Documentation:** [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## 8. AWS CLI Profile Configuration

The recommended development workflow uses a dedicated named AWS CLI profile. This keeps permanent credentials securely on your workstation:

```bash
# Configure named profile
aws configure --profile posture-dev

# Enter your IAM credentials:
# AWS Access Key ID [None]: <YOUR_ACCESS_KEY>
# AWS Secret Access Key [None]: <YOUR_SECRET_KEY>
# Default region name [None]: ap-south-1
# Default output format [None]: json
```

Verify profile authentication:
```bash
aws sts get-caller_identity --profile posture-dev
```

In `.env`, set:
```ini
AWS_PROFILE=posture-dev
AWS_DEFAULT_REGION=ap-south-1
AWS_SCAN_REGIONS=ap-south-1
```

---

## 9. S3 Bucket Creation and Configuration

Create a dedicated, private Amazon S3 bucket to store completed scan reports:

```bash
# 1. Create private bucket (example in ap-south-1)
aws s3api create-bucket \
  --bucket my-cloud-posture-audit-vault \
  --region ap-south-1 \
  --create-bucket-configuration LocationConstraint=ap-south-1 \
  --profile posture-dev

# 2. Enforce S3 Block Public Access (all 4 flags enabled)
aws s3api put-public-access-block \
  --bucket my-cloud-posture-audit-vault \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" \
  --profile posture-dev

# 3. Enable default server-side encryption (AES256)
aws s3api put-bucket-encryption \
  --bucket my-cloud-posture-audit-vault \
  --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}' \
  --profile posture-dev
```

---

## 10. IAM Permissions Required for Scanning and Report Storage

Follow the principle of least privilege. Attach the following custom inline IAM policy to your scanner IAM role or user:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCallerIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadOnlySecurityAssessment",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketAcl",
        "s3:GetPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "iam:GetAccountSummary",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReportBucketWriteAndRead",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-cloud-posture-audit-vault",
        "arn:aws:s3:::my-cloud-posture-audit-vault/scans/*"
      ]
    }
  ]
}
```

> **Security Note:** The scanner requires **read-only** discovery actions. Write permissions are strictly limited to your dedicated S3 report bucket and prefix (`scans/*`). The scanner never modifies, reconfigures, or deletes discovered infrastructure.

---

## 11. Environment Variable Setup

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Configure parameters:
```ini
# Named AWS CLI Profile
AWS_PROFILE=posture-dev

# Default AWS Region
AWS_DEFAULT_REGION=ap-south-1

# Comma-separated regions for multi-region EC2 discovery
AWS_SCAN_REGIONS=ap-south-1

# Dedicated Private S3 Storage Bucket
AWS_POSTURE_BUCKET=my-cloud-posture-audit-vault

# Force Simulation Mode (false connects to live AWS; true forces offline mock data)
USE_MOCK=false

# Server Configuration
HOST=0.0.0.0
PORT=8000
```

---

## 12. How to Run the Backend and Frontend

### Local Execution:
```bash
python run.py
```
The FastAPI application serves both the backend REST APIs and the compiled frontend dashboard at `http://localhost:8000/`.

### Docker Execution:
```bash
# Build and run container
docker compose up --build -d

# View live logs
docker compose logs -f
```

---

## 13. How to Run Automated Tests

The test suite validates mock discovery, live discovery error isolation, all security checks (Pass, Fail, and Permission Error states), S3 upload, retrieval, and failure handling:

```bash
# Run complete test suite
pytest

# Run with verbose output and coverage
pytest -v
```

---

## 14. Example API Endpoints and Responses

### `GET /health`
```json
{
  "status": "healthy",
  "timestamp": "2026-10-30T00:30:00.000000+00:00",
  "mode": "LIVE_AWS",
  "aws_connected": true,
  "connection_message": "Connected to AWS as arn:aws:iam::123456789012:user/posture-dev (Account: 123456789012)",
  "account_id": "123456789012",
  "active_profile": "posture-dev",
  "default_region": "ap-south-1",
  "scan_regions": ["ap-south-1"],
  "storage_bucket": "my-cloud-posture-audit-vault",
  "last_successful_scan_time": "2026-10-30T00:30:15.123456+00:00",
  "version": "1.0.0"
}
```

### `POST /scan`
Triggers an on-demand audit and persists findings to Amazon S3:
```json
{
  "scan_id": "7b82f1ac",
  "aws_account_id": "123456789012",
  "start_time": "2026-10-30T00:30:00.000000+00:00",
  "completion_time": "2026-10-30T00:30:12.456789+00:00",
  "timestamp": "2026-10-30T00:30:12.456789+00:00",
  "status": "COMPLETED",
  "mode": "LIVE_AWS",
  "target_regions": ["ap-south-1"],
  "instances": [],
  "buckets": [],
  "cis_results": [],
  "summary": {
    "total_checks": 8,
    "passed_checks": 6,
    "failed_checks": 2,
    "warning_checks": 0,
    "error_checks": 0,
    "unknown_checks": 0,
    "compliance_score_percent": 75.0,
    "critical_failures": 1,
    "high_failures": 1
  },
  "scan_errors": [],
  "storage": {
    "destination": "AWS-S3",
    "location": "s3://my-cloud-posture-audit-vault/scans/2026/10/30/7b82f1ac.json",
    "status": "SUCCESS",
    "encrypted": true
  }
}
```

### `GET /scans`
Retrieves scan history list from Amazon S3 or local development storage:
```json
[
  {
    "scan_id": "7b82f1ac",
    "timestamp": "2026-10-30T00:30:12.456789+00:00",
    "mode": "LIVE_AWS",
    "status": "COMPLETED",
    "compliance_score": 75.0,
    "total_checks": 8,
    "passed_checks": 6,
    "failed_checks": 2,
    "error_checks": 0,
    "instances_count": 4,
    "buckets_count": 3,
    "storage_destination": "AWS-S3",
    "storage_location": "s3://my-cloud-posture-audit-vault/scans/2026/10/30/7b82f1ac.json"
  }
]
```

### `GET /scans/{scan_id}`
Returns the complete scan report by scan ID. Returns `404 Not Found` if the scan ID does not exist.

---

## 15. Example Security Findings

### 1. Unrestricted Inbound SSH (CIS-4.1 - Critical)
```json
{
  "check_id": "CIS-4.1",
  "title": "Ensure No Security Groups Allow Ingress to SSH (Port 22) from 0.0.0.0/0 or ::/0",
  "category": "EC2 / Networking",
  "severity": "HIGH",
  "status": "FAIL",
  "resource_id": "sg-0192837465abc1234",
  "resource_type": "AWS::EC2::SecurityGroup",
  "evidence": "Security Group 'web-dmz-sg' (sg-0192837465abc1234) allows inbound TCP port 22 (SSH) from unrestricted sources (0.0.0.0/0 or ::/0). Exposed to internet-wide brute-force attacks.",
  "remediation": "aws ec2 revoke-security-group-ingress --group-id sg-0192837465abc1234 --protocol tcp --port 22 --cidr 0.0.0.0/0",
  "reference": "CIS AWS Foundations Benchmark v1.4.0 - Section 4.1 (v3.0.0 - 5.1)"
}
```

### 2. S3 Bucket Public Accessibility (CIS-2.1.1 - Critical)
```json
{
  "check_id": "CIS-2.1.1",
  "title": "Ensure S3 Bucket Access is Not Public",
  "category": "S3",
  "severity": "CRITICAL",
  "status": "FAIL",
  "resource_id": "company-public-marketing-assets",
  "resource_type": "AWS::S3::Bucket",
  "evidence": "Bucket 'company-public-marketing-assets' in region 'us-east-1' is publicly accessible. Findings: public bucket policy allows world access; ACL grants public Read/Write permissions; Public Access Block is disabled or incomplete.",
  "remediation": "aws s3api put-public-access-block --bucket company-public-marketing-assets --public-access-block-configuration \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\"",
  "reference": "CIS AWS Foundations Benchmark v1.4.0 - Section 2.1.1 (v3.0.0 - 2.1.4)"
}
```

### 3. Missing Root Account Multi-Factor Authentication (CIS-1.5 - Critical)
```json
{
  "check_id": "CIS-1.5",
  "title": "Ensure MFA is Enabled for the 'root' User Account",
  "category": "IAM",
  "severity": "CRITICAL",
  "status": "FAIL",
  "resource_id": "arn:aws:iam::123456789012:root",
  "resource_type": "AWS::IAM::RootAccount",
  "evidence": "The root user account for AWS account 123456789012 does NOT have Multi-Factor Authentication (MFA) enabled.",
  "remediation": "Sign into the AWS Management Console as the root user. Navigate to IAM > Security Credentials > Assign MFA Device to configure a virtual or hardware token.",
  "reference": "CIS AWS Foundations Benchmark v1.4.0 - Section 1.5 (v3.0.0 - 1.5)"
}
```

---

## 16. Known Limitations and Implemented Benchmark Scope

1. **Benchmark Version Alignment:** Evaluates controls referenced against **CIS AWS Foundations Benchmark v1.4.0** and mapped to **v3.0.0**. This tool covers core security controls (S3 Public Access, S3 Default Encryption, Root MFA, CloudTrail Active Logging, and Security Group SSH/RDP). It does not evaluate Level 2 benchmark controls such as custom CloudWatch metric alarms or complex IAM password policies.
2. **Read-Only Scope:** The scanner strictly performs read operations. It does not auto-remediate or modify customer cloud resources.
3. **Multi-Region Scope:** EC2 discovery scans regions configured in `AWS_SCAN_REGIONS`. Unlisted regions are skipped to conserve API quotas and reduce scan latency.
4. **API Errors as Non-Failures:** Missing IAM permissions or rate-limiting responses are classified as `ERROR` or `UNKNOWN` rather than security failures, preventing false alarms.

---

## 17. Security Considerations and Cleanup Instructions

### Security Best Practices
- **No Hardcoded Secrets:** Never commit `.env` or AWS access keys. `.gitignore` explicitly excludes `.env` and runtime data.
- **Dedicated S3 Bucket:** Store audit reports only in a dedicated, private S3 bucket with S3 Block Public Access enabled.
- **Least Privilege:** Run the scanner using an IAM role or temporary STS credentials rather than root or Administrator access.

### Cleanup Instructions
To delete temporary scan artifacts and tear down containers:
```bash
# 1. Stop Docker containers and remove volumes
docker compose down -v

# 2. Clean local cache and temporary test data
rm -rf data/history/*.json data/latest_scan.json .pytest_cache/ __pycache__/

# 3. Clean Python bytecode
find . -type d -name "__pycache__" -exec rm -rf {} +
```

To delete the S3 audit bucket in AWS when no longer needed:
```bash
aws s3 rm s3://my-cloud-posture-audit-vault --recursive --profile posture-dev
aws s3api delete-bucket --bucket my-cloud-posture-audit-vault --profile posture-dev
```
