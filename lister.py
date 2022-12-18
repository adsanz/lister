#!/usr/bin/python3
# -*- coding: utf-8 -*-
from secrets import choice
import json
import datetime
import argparse
import signal  # trap Ctrl-c for show_instance cleaner exit
from typing import Optional
import threading
from rich import box

import boto3
from botocore.exceptions import ProfileNotFound
from rich.json import JSON
from rich.console import Console
from rich.table import Table

# stubs
from mypy_boto3_ec2 import EC2ServiceResource

ERROR_STYLE = "bold red"
WARNING_STYLE = "bold yellow"
console = Console()


def parse_args(args: Optional[list] = None):
    if args is None:
        import sys

        args = sys.argv[1:]

    parser = argparse.ArgumentParser(
        description="""
    This script will list your ec2 instance with a given profile.
    You may also define a region, and you can also filter. A few examples:
    - Get all instances on the default profile region that has the tag "env" on value "beta"
      lister.py -p leo -fk "tag:env" -fv beta

    - Get all instances on the default profile region
      lister.py -p leo

    - Get all instances on region 'us-west-1' with profile leo and tag "env" on value "prod"
      lister.py -p leo -r us-west-1 -fk "tag:env" -fv beta

    - Get all instances on region us-west-1 with profile leo, with tag env set to prodp3,
     and role set to webserver
      lister.py -p leo -r us-west-1 -fk tag:env tag:role -fv prodp3 webservers

    - Complex filtering patterns!
      lister.py -p leo -r us-west-2 -fk tag:env tag:role -fv staging,beta webservers

    -  Get details from an instance
      lister.py -p leo -i i-1234567890abcdef0

    - Find out how many instances per region you have
      lister.py -p leo -l

    WARNING: if no region is defined, a random one will be used.
    """,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-r",
        "--region",
        help="Region to be used for ec2 listing. Default: choose a region at random.",
        default=None,
    )
    parser.add_argument(
        "-p",
        "--profile",
        help="Profile to authenticate",
        required=True,
        type=str,
    )
    parser.add_argument(
        "-fk",
        "--filter_key",
        help="Key used for filtering",
        default=None,
        nargs="*",
    )
    parser.add_argument(
        "-fv",
        "--filter_value",
        help="Value used for filtering (one or more)",
        default=None,
        nargs="*",
    )
    parser.add_argument(
        "-i",
        "--instance-id",
        help="Get instance details nicely formatted",
        default=None,
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="Amount of instances per region (one or more)",
        default=False,
    )

    parser.add_argument(
        "--rich-traceback",
        action="store_true",
        help="Rich traceback. Default: regular traceback.",
        default=False,
    )
    parser.add_argument(
        "-ls",
        "--localstack",
        action="store_true",
        help="Debug mode. Default: False.",
        default=False,
    )
    parser.add_argument(
        "-nst",
        "--not-show-tags",
        action="store_true",
        help="Show tags. Default: False)",
        default=False,
    )

    return vars(parser.parse_args(args))


def handler(signum, frame) -> None:
    """
    Handles Ctrl-C on show_instances() for a clean exit.
    """
    console.log(":warning: Ctrl-C detected. Exiting lister...", style="bold yellow")
    exit(2)


def region_lister(profile: str, args: dict) -> list:
    """
    List all regions from AWS instead of hardcoding them.

    Args:
        profile: AWS profile to be used.
    Return:
        List of regions.
    """
    session = boto3.Session(profile_name=profile, region_name="us-east-1")
    if args.get("localstack"):
        client = session.client("ec2", endpoint_url="http://localhost:4566")
    else:
        client = session.client("ec2")

    return [region["RegionName"] for region in client.describe_regions()["Regions"]]


def get_ec2(
    profile: str, regions: list, args: dict, region: Optional[str] = None
) -> EC2ServiceResource:
    """
    Return a boto3 ec2 session object.

    Args:
        profile: AWS profile to be used.
        regions: list of available regions.
        region: AWS region to be used.
    Return:
        boto3 ec2 session object.
    """
    if region is None:
        try:
            session = boto3.Session(profile_name=profile, region_name=region)
            if args.get("localstack"):
                return session.resource("ec2", endpoint_url="http://localhost:4566")
            else:
                return session.resource("ec2")
        except Exception:
            region = choice(regions)
            console.log(
                f""":warning: No region defined.
                Using [bold underline white on black]{region}[/] as profile region.""",
                style=WARNING_STYLE,
            )

    elif region not in regions:
        console.log(
            f":warning: Region {region} is not valid. Exiting...", style=ERROR_STYLE
        )
        exit(1)

    session = boto3.Session(profile_name=profile, region_name=region)
    if args.get("localstack"):
        return session.resource("ec2", endpoint_url="http://localhost:4566")
    else:
        return session.resource("ec2")


class lister_threading(threading.Thread):
    """
    Get all instance on a given region.

    Args:
        region (str): AWS region to be used.

    Return:
        None (logs to console).
    """

    def __init__(
        self, profile: str, region: str, regions: list, arg_list: dict, *args, **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.region = region
        self.regions = regions
        self.args = arg_list
        self.profile = profile

    def run(self) -> None:
        if self.args.get("list"):
            ec2 = get_ec2(
                profile=self.profile,
                regions=self.regions,
                region=self.region,
                args=self.args,
            )
            instances = list(ec2.instances.all())

            color = "white"
            style = "bold green"
            if not instances:
                color = "red"
                style = ERROR_STYLE

            msg = (
                f"Found [bold underline {color} on black]{len(instances)}[/] instances on"
                f"region [bold underline white on black]{self.region}[/]"
            )
            console.log(msg, style=style)
        else:
            """
            Future reference might use threading anywhere else.
            """
            pass


def lister(regions: list, args: dict) -> None:
    """
    List how many instances we have for each region.

    Args:
        regions: list of available regions.
    Return:
        Nothing.
    """
    threads = []
    with console.status("[bold green]Getting instances... [/]", spinner="dots"):
        for region in regions:
            thread = lister_threading(
                region=region,
                profile=str(args.get("profile")),
                regions=regions,
                arg_list=args,
            )
            thread.start()
            threads.append(thread)
        for thread in threads:
            if thread.is_alive():
                thread.join(1)


def show_instance(ec2: EC2ServiceResource, instance_id: str) -> None:
    """
    Print in a table details of a specified instance

    Args:
        ec2: boto3 ec2 session object.
        instance_id: Instance ID to be used.
    Return:
        Nothing.
    """
    with console.status("[bold green]Getting instances...", spinner="dots"):
        instance = ec2.Instance(instance_id)
        table = Table(
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
            box=box.SQUARE_DOUBLE_HEAD,
        )
        table.add_column("Attribute", style="white bold dim", width=30)
        table.add_column("Value", style="white dim")
        table.add_row("Instance ID", instance.id)
        table.add_row("Instance Type", instance.instance_type)
        table.add_row("Instance State", instance.state["Name"])
        table.add_row("Instance Launch Time", str(instance.launch_time))
        table.add_row("Instance Public IP", instance.public_ip_address)
        table.add_row("Instance Private IP", instance.private_ip_address)
        table.add_row("Instance Public DNS", instance.public_dns_name)
        table.add_row("Instance Private DNS", instance.private_dns_name)
        table.add_row("Instance Key Name", instance.key_name)
        table.add_row(
            "Instance IAM Role", JSON(json.dumps(instance.iam_instance_profile))
        )
        table.add_row("Instance VPC ID", instance.vpc_id)
        table.add_row("Instance Subnet ID", instance.subnet_id)
        table.add_row(
            "Instance Security Groups", JSON(json.dumps(instance.security_groups))
        )
        table.add_row("Instance Tags", JSON(json.dumps(instance.tags)))
    console.print(table)


def build_filter(args: dict) -> list:
    """
    Return a list of filters to use when gathering instances.

    Args:
        args: dict of arguments passed to the script.
    Return:
        List of filters.

    """
    if args["filter_key"] is not None and args["filter_value"] is not None:
        filter = [{"Name": "instance-state-name", "Values": ["running"]}]
        # allow multiple sets of filter keys and values
        for fk, fv in zip(args["filter_key"], args["filter_value"]):
            if "," in fv:
                filter_list = [{"Name": fk, "Values": fv.split(",")}]
            else:
                filter_list = [{"Name": fk, "Values": [fv]}]
            filter += filter_list
    else:
        filter = [{"Name": "instance-state-name", "Values": ["running"]}]
    return filter


def main_list(ec2: EC2ServiceResource, args: dict) -> None:

    filter = build_filter(args)
    ec2_list = []
    tag_key: list = []
    tag_value: list = []
    with console.status("[bold green]Listing instances...", spinner="dots"):
        for instance in ec2.instances.filter(Filters=filter):
            uptime = (datetime.datetime.now().astimezone() - instance.launch_time).days
            pub_ip = instance.public_ip_address
            name = ""

            # No need to check if private IPs are empty, since AWS will always assign a private IP to instances
            priv_ip_list = []
            for priv_ip in instance.network_interfaces_attribute:
                priv_ip_list.append(priv_ip["PrivateIpAddress"])

            if instance.tags:
                for tags in instance.tags:
                    if tags["Key"] == "Name":
                        name = tags["Value"]
                    tag_key, tag_value = [tag["Key"] for tag in instance.tags], [
                        tag["Value"] for tag in instance.tags
                    ]

                if args.get("not_show_tags"):
                    tag_key = []
                    tag_value = []

                elif len(tag_key) > 3:
                    console.print(
                        f"[bold red]Instance {instance.id} has more than 3 tags, only the first 3 will be shown.[/]"
                    )
                    tag_key = tag_key[:3]
                    tag_value = tag_value[:3]

            ec2_list.append(
                [
                    instance.instance_id,
                    name,
                    pub_ip,
                    ", ".join(priv_ip_list),
                    str(uptime) + " Days",
                    f"[bold underline]Keys:[/] {tag_key}\n[bold underline]Values[/]: {tag_value}",
                ]
            )

        ec2_table = Table(
            title="EC2 Instances",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
            box=box.SQUARE_DOUBLE_HEAD,
        )

        for header in [
            "Instance ID",
            "Name",
            "Public IP",
            "Private IP",
            "Uptime (days)",
            "Tags",
        ]:
            ec2_table.add_column(header, justify="left", style="cyan", no_wrap=True)

        for row in ec2_list:
            ec2_table.add_row(*row)

    console.print(ec2_table)

def main():
    args = parse_args()

    signal.signal(signal.SIGINT, handler)

    if args.get("rich_traceback"):
        from rich.traceback import install

        install(show_locals=True)

    profile_name = args.get("profile")
    region_name = args.get("region")

    try:
        regions = region_lister(profile=profile_name, args=args)
    except ProfileNotFound:
        console.log(
            f":warning: Profile '{profile_name}' is not valid. Exiting...",
            style=ERROR_STYLE,
        )
        exit(1)

    ec2 = get_ec2(profile=profile_name, regions=regions, region=region_name, args=args)

    if args.get("list"):
        lister(regions=regions, args=args)

    elif args.get("instance_id"):
        show_instance(ec2=ec2, instance_id=args.get("instance_id"))

    else:
        main_list(ec2=ec2, args=args)


if __name__ == "__main__":
    main()
