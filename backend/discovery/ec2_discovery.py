"""
EC2 and Security Group Discovery Module.
Discovers all EC2 instances and associated security groups across configured AWS regions.
Distinguishes genuinely empty inventories from API and permission failures.
"""
import logging
from typing import List, Dict, Any, Tuple
from botocore.exceptions import ClientError, BotoCoreError
from backend.core.aws_client import aws_manager
from backend.models.schemas import EC2Instance, SecurityGroupSummary
from backend.mock_data import get_mock_ec2_instances
from backend.config import settings

logger = logging.getLogger("cloud_posture.ec2_discovery")


def inspect_security_group(sg: Dict[str, Any]) -> SecurityGroupSummary:
    """Inspects an AWS security group for open ingress rules (SSH, RDP, etc.)."""
    group_id = sg.get("GroupId", "")
    group_name = sg.get("GroupName", "")
    desc = sg.get("Description", "")
    vpc_id = sg.get("VpcId", "")

    allows_all_ssh = False
    allows_all_rdp = False
    open_rules: List[str] = []

    for perm in sg.get("IpPermissions", []):
        ip_protocol = perm.get("IpProtocol", "")
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        # Check IPv4 CIDR ranges
        for ip_range in perm.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            is_world_open = (cidr == "0.0.0.0/0")

            rule_desc = f"{ip_protocol.upper()} {from_port}-{to_port} from {cidr}" if from_port != to_port else f"{ip_protocol.upper()} {from_port} from {cidr}"
            if ip_protocol == "-1":
                rule_desc = f"ALL TRAFFIC from {cidr}"

            if is_world_open:
                # Port 22 (SSH) or all traffic
                if ip_protocol == "-1" or (from_port is not None and to_port is not None and from_port <= 22 <= to_port):
                    allows_all_ssh = True
                # Port 3389 (RDP) or all traffic
                if ip_protocol == "-1" or (from_port is not None and to_port is not None and from_port <= 3389 <= to_port):
                    allows_all_rdp = True

            open_rules.append(rule_desc)

        # Check IPv6 CIDR ranges
        for ip_range in perm.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6", "")
            is_world_open = (cidr == "::/0")
            rule_desc = f"{ip_protocol.upper()} {from_port}-{to_port} from {cidr} (IPv6)" if from_port != to_port else f"{ip_protocol.upper()} {from_port} from {cidr} (IPv6)"

            if is_world_open:
                if ip_protocol == "-1" or (from_port is not None and to_port is not None and from_port <= 22 <= to_port):
                    allows_all_ssh = True
                if ip_protocol == "-1" or (from_port is not None and to_port is not None and from_port <= 3389 <= to_port):
                    allows_all_rdp = True

            open_rules.append(rule_desc)

    return SecurityGroupSummary(
        group_id=group_id,
        group_name=group_name,
        description=desc,
        vpc_id=vpc_id,
        allows_all_ssh=allows_all_ssh,
        allows_all_rdp=allows_all_rdp,
        open_inbound_rules=open_rules,
    )


def discover_ec2_resources(
    regions: List[str] = None,
) -> Tuple[List[EC2Instance], List[SecurityGroupSummary], List[str]]:
    """
    Discovers EC2 instances and security groups across target AWS regions.
    Returns: (discovered_instances, all_security_groups, scan_errors)
    """
    if aws_manager.is_mock_mode():
        logger.info("Operating in Mock/Simulation mode: returning realistic mock EC2 data.")
        mock_instances = get_mock_ec2_instances()
        all_sgs = [sg for inst in mock_instances for sg in inst.security_groups]
        return mock_instances, all_sgs, []

    target_regions = regions or settings.SCAN_REGIONS
    discovered_instances: List[EC2Instance] = []
    all_discovered_sgs: Dict[str, SecurityGroupSummary] = {}
    scan_errors: List[str] = []

    for region in target_regions:
        try:
            logger.info(f"Scanning EC2 inventory in region: {region}")
            ec2_client = aws_manager.get_client("ec2", region_name=region)

            # 1. Fetch security groups in this region
            try:
                sg_paginator = ec2_client.get_paginator("describe_security_groups")
                for page in sg_paginator.paginate():
                    for sg_data in page.get("SecurityGroups", []):
                        sg_summary = inspect_security_group(sg_data)
                        all_discovered_sgs[sg_summary.group_id] = sg_summary
            except (ClientError, BotoCoreError) as e:
                err_msg = f"Failed to describe security groups in {region}: {e}"
                logger.warning(err_msg)
                scan_errors.append(err_msg)

            # 2. Fetch EC2 instances
            try:
                paginator = ec2_client.get_paginator("describe_instances")
                for page in paginator.paginate():
                    for reservation in page.get("Reservations", []):
                        for inst in reservation.get("Instances", []):
                            instance_id = inst.get("InstanceId", "")
                            instance_type = inst.get("InstanceType", "unknown")
                            state = inst.get("State", {}).get("Name", "unknown")
                            public_ip = inst.get("PublicIpAddress")
                            private_ip = inst.get("PrivateIpAddress")
                            vpc_id = inst.get("VpcId")
                            launch_time = inst.get("LaunchTime")
                            launch_str = launch_time.isoformat() if launch_time else None

                            # Resolve Name tag
                            name = "Unnamed"
                            for tag in inst.get("Tags", []):
                                if tag.get("Key") == "Name":
                                    name = tag.get("Value", "Unnamed")
                                    break

                            # Map attached security groups
                            attached_sgs: List[SecurityGroupSummary] = []
                            for sg_ref in inst.get("SecurityGroups", []):
                                sg_id = sg_ref.get("GroupId")
                                if sg_id in all_discovered_sgs:
                                    attached_sgs.append(all_discovered_sgs[sg_id])
                                else:
                                    attached_sgs.append(
                                        SecurityGroupSummary(
                                            group_id=sg_id,
                                            group_name=sg_ref.get("GroupName", ""),
                                        )
                                    )

                            discovered_instances.append(
                                EC2Instance(
                                    instance_id=instance_id,
                                    name=name,
                                    instance_type=instance_type,
                                    region=region,
                                    state=state,
                                    public_ip=public_ip,
                                    private_ip=private_ip,
                                    vpc_id=vpc_id,
                                    security_groups=attached_sgs,
                                    launch_time=launch_str,
                                )
                            )
            except (ClientError, BotoCoreError) as e:
                err_msg = f"Failed to describe EC2 instances in {region}: {e}"
                logger.error(err_msg)
                scan_errors.append(err_msg)

        except Exception as e:
            err_msg = f"Unexpected error during EC2 discovery in region {region}: {e}"
            logger.error(err_msg)
            scan_errors.append(err_msg)

    return discovered_instances, list(all_discovered_sgs.values()), scan_errors


def discover_ec2_instances(
    regions: List[str] = None,
) -> Tuple[List[EC2Instance], List[SecurityGroupSummary]]:
    """Legacy compatibility wrapper returning (instances, sgs)."""
    instances, sgs, _ = discover_ec2_resources(regions=regions)
    return instances, sgs
