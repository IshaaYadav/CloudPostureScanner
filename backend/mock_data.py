"""
Realistic cloud infrastructure mock data for zero-config demonstration and testing.
Provides EC2, S3, IAM, CloudTrail, and Security Group resources reflecting real-world setups.
"""
from typing import List, Dict, Any
from backend.models.schemas import (
    EC2Instance,
    SecurityGroupSummary,
    S3Bucket,
    S3PublicAccessBlock,
)


def get_mock_ec2_instances() -> List[EC2Instance]:
    return [
        EC2Instance(
            instance_id="i-0a89d71c42f01234a",
            name="Prod-WebServer-01",
            instance_type="t2.micro",
            region="us-east-1",
            state="running",
            public_ip="54.210.12.34",
            private_ip="172.31.16.45",
            vpc_id="vpc-0a1b2c3d4e5f67890",
            security_groups=[
                SecurityGroupSummary(
                    group_id="sg-0192837465abc1234",
                    group_name="web-dmz-sg",
                    description="Public web server ingress",
                    vpc_id="vpc-0a1b2c3d4e5f67890",
                    allows_all_ssh=True,
                    allows_all_rdp=False,
                    open_inbound_rules=[
                        "TCP 80 from 0.0.0.0/0 (HTTP)",
                        "TCP 443 from 0.0.0.0/0 (HTTPS)",
                        "TCP 22 from 0.0.0.0/0 (SSH - HIGH RISK)",
                    ],
                )
            ],
            launch_time="2026-09-15T08:30:00Z",
        ),
        EC2Instance(
            instance_id="i-0b73c91e53a15678b",
            name="Internal-Postgres-Primary",
            instance_type="t3.micro",
            region="us-east-1",
            state="running",
            public_ip=None,
            private_ip="10.0.1.88",
            vpc_id="vpc-0a1b2c3d4e5f67890",
            security_groups=[
                SecurityGroupSummary(
                    group_id="sg-0987654321fed9876",
                    group_name="database-isolated-sg",
                    description="Private database tier",
                    vpc_id="vpc-0a1b2c3d4e5f67890",
                    allows_all_ssh=False,
                    allows_all_rdp=False,
                    open_inbound_rules=[
                        "TCP 5432 from 10.0.0.0/16 (PostgreSQL Private)",
                    ],
                )
            ],
            launch_time="2026-08-20T14:15:00Z",
        ),
        EC2Instance(
            instance_id="i-0c12e84d64b29876c",
            name="Windows-Bastion-Host",
            instance_type="t2.small",
            region="us-west-2",
            state="running",
            public_ip="34.218.99.102",
            private_ip="172.20.10.15",
            vpc_id="vpc-0f9e8d7c6b5a43210",
            security_groups=[
                SecurityGroupSummary(
                    group_id="sg-0564738291def5678",
                    group_name="remote-admin-sg",
                    description="Administrative remote desktop access",
                    vpc_id="vpc-0f9e8d7c6b5a43210",
                    allows_all_ssh=False,
                    allows_all_rdp=True,
                    open_inbound_rules=[
                        "TCP 3389 from 0.0.0.0/0 (RDP - CRITICAL RISK)",
                    ],
                )
            ],
            launch_time="2026-10-01T11:00:00Z",
        ),
        EC2Instance(
            instance_id="i-0d99a22f75c34567d",
            name="Async-Batch-Worker",
            instance_type="t3.nano",
            region="eu-west-1",
            state="stopped",
            public_ip=None,
            private_ip="10.2.3.44",
            vpc_id="vpc-01122334455667788",
            security_groups=[
                SecurityGroupSummary(
                    group_id="sg-08877665544332211",
                    group_name="batch-worker-sg",
                    description="Batch worker SG",
                    vpc_id="vpc-01122334455667788",
                    allows_all_ssh=False,
                    allows_all_rdp=False,
                    open_inbound_rules=[],
                )
            ],
            launch_time="2026-07-10T19:45:00Z",
        ),
    ]


def get_mock_s3_buckets() -> List[S3Bucket]:
    return [
        S3Bucket(
            bucket_name="company-public-marketing-assets",
            region="us-east-1",
            creation_date="2026-01-12T10:00:00Z",
            encryption_status="SSE-S3 (AES256)",
            access_policy="Public",
            public_access_block=S3PublicAccessBlock(
                block_public_acls=False,
                ignore_public_acls=False,
                block_public_policy=False,
                restrict_public_buckets=False,
                configured=True,
            ),
            has_public_policy=True,
            has_public_acl=True,
            versioning_status="Disabled",
            evidence_notes="Public Access Block disabled; public policy and ACL grants detected",
        ),
        S3Bucket(
            bucket_name="fintech-compliance-audit-vault",
            region="us-east-1",
            creation_date="2026-03-24T16:20:00Z",
            encryption_status="SSE-KMS",
            kms_key_id="arn:aws:kms:us-east-1:123456789012:key/8a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
            access_policy="Private",
            public_access_block=S3PublicAccessBlock(
                block_public_acls=True,
                ignore_public_acls=True,
                block_public_policy=True,
                restrict_public_buckets=True,
                configured=True,
            ),
            has_public_policy=False,
            has_public_acl=False,
            versioning_status="Enabled",
            evidence_notes="Public Access Block fully enabled; private bucket policy",
        ),
        S3Bucket(
            bucket_name="legacy-customer-exports-2023",
            region="us-west-2",
            creation_date="2025-11-05T09:12:00Z",
            encryption_status="Unencrypted",
            access_policy="Private",
            public_access_block=S3PublicAccessBlock(
                block_public_acls=True,
                ignore_public_acls=True,
                block_public_policy=True,
                restrict_public_buckets=True,
                configured=True,
            ),
            has_public_policy=False,
            has_public_acl=False,
            versioning_status="Suspended",
            evidence_notes="Public Access Block fully enabled; unencrypted storage",
        ),
        S3Bucket(
            bucket_name="iot-telemetry-raw-logs",
            region="eu-west-1",
            creation_date="2026-06-18T13:40:00Z",
            encryption_status="SSE-S3 (AES256)",
            access_policy="Public",
            public_access_block=S3PublicAccessBlock(
                block_public_acls=False,
                ignore_public_acls=False,
                block_public_policy=False,
                restrict_public_buckets=False,
                configured=True,
            ),
            has_public_policy=True,
            has_public_acl=False,
            versioning_status="Enabled",
            evidence_notes="Public Access Block disabled; public bucket policy attached",
        ),
    ]


def get_mock_iam_posture() -> Dict[str, Any]:
    return {
        "root_mfa_enabled": False,  # CIS 1.5 FAIL
        "root_access_keys_present": False,
        "account_id": "123456789012",
        "alias": "demo-fintech-sandbox",
    }


def get_mock_cloudtrail_posture() -> Dict[str, Any]:
    return {
        "trails": [
            {
                "name": "management-events-trail",
                "is_multi_region": False,  # CIS 3.1 FAIL (not multi-region)
                "is_logging": True,
                "s3_bucket": "cloudtrail-logs-us-east-1",
                "log_file_validation_enabled": False,
                "home_region": "us-east-1",
            }
        ]
    }

