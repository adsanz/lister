from secrets import choice
import json
import datetime
import argparse
import signal  # trap Ctrl-c for show_instance cleaner exit
from typing import Optional
from threading import Thread
from rich import box
from os import environ
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

    - If you don't require a profile, env variables are supported, just omit the -p flag (it requires -r)
      lister.py -r eu-west-1 -l

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
        required=False,
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


def credentials_handler(
    region_name: str, profile: Optional[str] = None
) -> boto3.session.Session:
    """
    This function decides if we use a profile or if we stick to environment credentials.
    """
    key_id = environ.get("AWS_ACCESS_KEY_ID")
    secret_key = environ.get("AWS_SECRET_ACCESS_KEY")
    if environ.get("AWS_SESSION_TOKEN"):
        session_token = environ.get("AWS_SESSION_TOKEN")
    if key_id and secret_key:
        if session_token:
            session = boto3.Session(
                region_name=region_name,
                aws_access_key_id=key_id,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token,
            )
        else:
            session = boto3.Session(
                region_name=region_name,
                aws_access_key_id=key_id,
                aws_secret_access_key=secret_key,
            )
    else:
        try:
            session = boto3.Session(profile_name=profile, region_name=region_name)
        except ProfileNotFound as e:
            console.log(
                f":warning: Profile {profile} not found. Exiting...", style=ERROR_STYLE
            )
            console.error(e)
            exit(1)
    return session


def region_lister(options: dict, profile: Optional[str] = None) -> list:
    """
    List all regions from AWS instead of hardcoding them.

    Args:
        profile: AWS profile to be used.
        options: dictionary of options.
    Return:
        List of regions.
    """
    session = credentials_handler("us-east-1", profile)

    if options.get("localstack"):
        client = session.client("ec2", endpoint_url="http://localhost:4566")
    else:
        client = session.client("ec2")

    return [region["RegionName"] for region in client.describe_regions()["Regions"]]


def get_ec2(
    regions: list,
    options: dict,
    region: Optional[str] = None,
    profile: Optional[str] = None,
) -> EC2ServiceResource:
    """
    Return a boto3 ec2 session object.

    Args:
        profile: AWS profile to be used.
        regions: list of available regions.
        region: AWS region to be used.
        options: dictionary with options.
    Return:
        boto3 ec2 session object.
    """
    session = credentials_handler(region, profile)
    if region is None:
        try:
            if options.get("localstack"):
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

    if options.get("localstack"):
        return session.resource("ec2", endpoint_url="http://localhost:4566")
    else:
        return session.resource("ec2")


class ListerThreading(Thread):
    """
    Get all instances on a given region.

    Args:
        region (str): AWS region to be used.
    Return:
        None (logs to console).
    """

    def __init__(
        self, profile: str, region: str, regions: list, arg_list: dict, *args, **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self.config = {
            "profile": profile,
            "region": region,
            "regions": regions,
            "options": arg_list,
        }
        for key, value in self.config.items():
            setattr(self, key, value)

    def run(self) -> None:
        if self.options.get("list"):
            ec2 = get_ec2(**self.config)
            instances = list(ec2.instances.all())
            color, style = (
                ("red", ERROR_STYLE) if not instances else ("white", "bold green")
            )
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

    def start(self) -> "ListerThreading":
        super().start()
        return self


def lister(regions: list, options: dict) -> None:
    """
    List how many instances we have for each region.

    Args:
        regions: list of available regions.
        options: dictionary with options.
    Return:
        Nothing.
    """
    threads = []
    with console.status("[bold green]Getting instances... [/]", spinner="dots"):
        threads = [
            ListerThreading(
                region=region,
                profile=str(options.get("profile")),
                regions=regions,
                arg_list=options,
            ).start()
            for region in regions
        ]

        [thread.join(1) for thread in threads if thread.is_alive()]


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
        row_names = (
            "ID",
            "Type",
            "State",
            "Launch Time",
            "Public IP",
            "Private IP",
            "Public DNS",
            "Private DNS",
            "Key Name",
            "IAM Role",
            "VPC ID",
            "Subnet ID",
            "Security Groups",
            "Tags",
        )

        row_values = (
            instance.id,
            instance.instance_type,
            instance.state["Name"],
            str(instance.launch_time),
            instance.public_ip_address,
            instance.private_ip_address,
            instance.public_dns_name,
            instance.private_dns_name,
            instance.key_name,
            JSON(json.dumps(instance.iam_instance_profile)),
            instance.vpc_id,
            instance.subnet_id,
            JSON(json.dumps(instance.security_groups)),
            JSON(json.dumps(instance.tags)),
        )

        for name, value in zip(row_names, row_values):
            table.add_row(f"Instance {name}", value)

    console.print(table)


def build_filter(args: dict) -> list:
    """
    Return a list of filters to use when gathering instances.

    Args:
        args: dict of arguments passed to the script.
    Return:
        List of filters.

    """
    filter_list = [{"Name": "instance-state-name", "Values": ["running"]}]
    filter_params = (args.get("filter_key", []), args.get("filter_value", []))
    if filter_params != (None, None):
        filter_list.extend(
            [{"Name": fk, "Values": fv.split(",")} for fk, fv in zip(*filter_params)]
        )
    return filter_list


def main_list(ec2: EC2ServiceResource, args: dict) -> None:
    filter = build_filter(args)
    ec2_list, tag_key, tag_value = list(), list(), list()

    with console.status("[bold green]Listing instances...", spinner="dots"):
        for instance in ec2.instances.filter(Filters=filter):
            uptime = (datetime.datetime.now().astimezone() - instance.launch_time).days
            pub_ip = instance.public_ip_address
            name = ""

            # No need to check if private IPs are empty, since AWS will always assign a private IP to instances
            priv_ip_list = [
                priv_ip["PrivateIpAddress"]
                for priv_ip in instance.network_interfaces_attribute
            ]

            instance_tags = instance.tags if instance.tags else list()
            tag_key, tag_value = [tag["Key"] for tag in instance.tags], [
                tag["Value"] for tag in instance.tags
            ]

            name = (
                [tags["Value"] for tags in instance_tags if tags["Key"] == "Name"]
                + [name]
            )[0]

            if args.get("not_show_tags"):
                tag_key, tag_value = None, None
            else:
                if len(tag_key) > 3:
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

        params = dict(justify="left", style="cyan", no_wrap=True)
        headers = [
            "Instance ID",
            "Name",
            "Public IP",
            "Private IP",
            "Uptime (days)",
            "Tags",
        ]

        [ec2_table.add_column(header, **params) for header in headers]
        [ec2_table.add_row(*row) for row in ec2_list]

    console.print(ec2_table)


def main():
    opts = parse_args()

    signal.signal(signal.SIGINT, handler)

    if opts.get("rich_traceback"):
        from rich.traceback import install

        install(show_locals=True)

    if opts.get("profile"):
        profile_name = opts.get("profile")
    region_name = opts.get("region")

    try:
        regions = (
            region_lister(profile=profile_name, options=opts)
            if opts.get("profile")
            else region_lister(options=opts)
        )
    except ProfileNotFound:
        console.log(
            f":warning: Profile '{profile_name}' is not valid. Exiting...",
            style=ERROR_STYLE,
        )
        raise

    ec2 = (
        get_ec2(profile=profile_name, regions=regions, region=region_name, options=opts)
        if opts.get("profile")
        else get_ec2(regions=regions, region=region_name, options=opts)
    )

    if opts.get("list"):
        lister(regions=regions, options=opts)

    elif opts.get("instance_id"):
        show_instance(ec2=ec2, instance_id=opts.get("instance_id"))

    else:
        main_list(ec2=ec2, args=opts)


if __name__ == "__main__":
    main()
