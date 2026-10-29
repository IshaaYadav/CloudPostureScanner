"""
Tests for Resource Discovery (EC2 & S3).
Verifies rule parsing, mock discovery, live client pagination, and error isolation.
"""
from unittest.mock import MagicMock, patch
import pytest
from botocore.exceptions import ClientError

from backend.discovery.ec2_discovery import (
    discover_ec2_instances,
    discover_ec2_resources,
    inspect_security_group,
)
from backend.discovery.s3_discovery import (
    discover_s3_buckets,
    discover_s3_resources,
    evaluate_bucket_public_access,
    get_bucket_encryption_details,
)
from backend.core.aws_client import aws_manager


def test_inspect_security_group_ssh_open_ipv4():
    sg_raw = {
        "GroupId": "sg-open-ssh",
        "GroupName": "ssh-open-sg",
        "Description": "Test SG with open SSH",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    }
    summary = inspect_security_group(sg_raw)
    assert summary.group_id == "sg-open-ssh"
    assert summary.allows_all_ssh is True
    assert summary.allows_all_rdp is False
    assert len(summary.open_inbound_rules) == 1


def test_inspect_security_group_ssh_open_ipv6():
    sg_raw = {
        "GroupId": "sg-ipv6-ssh",
        "GroupName": "ipv6-ssh-sg",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 20,
                "ToPort": 25,
                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
            }
        ],
    }
    summary = inspect_security_group(sg_raw)
    assert summary.allows_all_ssh is True


def test_inspect_security_group_all_traffic():
    sg_raw = {
        "GroupId": "sg-all-traffic",
        "GroupName": "all-traffic-sg",
        "IpPermissions": [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    }
    summary = inspect_security_group(sg_raw)
    assert summary.allows_all_ssh is True
    assert summary.allows_all_rdp is True


def test_inspect_security_group_safe_internal():
    sg_raw = {
        "GroupId": "sg-safe",
        "GroupName": "internal-sg",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
            }
        ],
    }
    summary = inspect_security_group(sg_raw)
    assert summary.allows_all_ssh is False
    assert summary.allows_all_rdp is False


def test_discover_ec2_instances_mock():
    aws_manager.force_mock_mode(True)
    instances, sgs, errors = discover_ec2_resources()

    assert len(instances) > 0
    assert len(errors) == 0
    first = instances[0]
    assert hasattr(first, "instance_id") and first.instance_id.startswith("i-")
    assert hasattr(first, "instance_type")
    assert hasattr(first, "region")
    assert hasattr(first, "public_ip")
    assert hasattr(first, "security_groups")
    assert len(first.security_groups) > 0


def test_discover_ec2_live_permission_error():
    mock_ec2 = MagicMock()
    mock_ec2.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "Not authorized"}},
        "DescribeInstances",
    )

    with patch.object(aws_manager, "is_mock_mode", return_value=False), \
         patch.object(aws_manager, "get_client", return_value=mock_ec2):

        instances, sgs, errors = discover_ec2_resources(regions=["ap-south-1"])
        assert len(instances) == 0
        assert len(errors) > 0
        assert "UnauthorizedOperation" in errors[0]


def test_discover_s3_buckets_mock():
    aws_manager.force_mock_mode(True)
    buckets, errors = discover_s3_resources()

    assert len(buckets) > 0
    assert len(errors) == 0
    first = buckets[0]
    assert hasattr(first, "bucket_name")
    assert hasattr(first, "region")
    assert hasattr(first, "encryption_status")
    assert hasattr(first, "access_policy")
    assert first.access_policy in ("Public", "Private")


def test_discover_s3_live_permission_error():
    mock_s3 = MagicMock()
    mock_s3.list_buckets.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
        "ListBuckets",
    )

    with patch.object(aws_manager, "is_mock_mode", return_value=False), \
         patch.object(aws_manager, "get_client", return_value=mock_s3):

        buckets, errors = discover_s3_resources()
        assert len(buckets) == 0
        assert len(errors) > 0
        assert "AccessDenied" in errors[0]
