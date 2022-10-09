#!/usr/bin/python3

from secrets import choice
import json
import datetime
import argparse
import boto3
from rich.json import JSON
from rich.console import Console
from rich.table import Table
# Trap ctrl-c for show_instance clearner exit
import signal
# Automatic rich traceback handler
NICE_TRACEBACK = False
if NICE_TRACEBACK:
    from rich.traceback import install
    install(show_locals=True)   


parser = argparse.ArgumentParser(description="""
This script will list your ec2 instance with a given profile.
You may also define a region (if not configured on the profile this is required), and you can filter. A few examples:
- Get all instances on the default profile region that has the tag "env" on value "beta"
  lister.py -p leo -fk "tag:env" -fv beta

- Get all instances on the default profile region
  lister.py -p leo

- Get all instances on region 'us-west-1' with profile leo and tag "env" on value "prod"
  lister.py -p leo -r us-west-1 -fk "tag:env" -fv beta

- Get all instances on region us-west-1 with profile leo, with tag env set to prodp3, and role set to webserver
  lister.py -p leo -r us-west-1 -fk tag:env tag:role -fv prodp3 webservers

- Complex filtering patterns!
  lister.py -p leo -r us-west-2 -fk tag:env tag:role -fv staging,beta webservers

-  Get details from an instance
  lister.py -p leo -i i-1234567890abcdef0

- Find out how many instances per region you have
  lister.py -p leo -l

WARNING: if no region is defined, a random one will be used.

""", formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-r','--region', help='Region to be used for ec2 listing', required=False, default=None)
parser.add_argument('-p','--profile', help='Profile to authenticate', required=True)
parser.add_argument('-fk','--filter_key', help='Key used for filtering', required=False, default=None, nargs='*')
parser.add_argument('-fv','--filter_value', help='Value used for filtering (one or more)', required=False, default=None, nargs='*')
parser.add_argument('-i','--instance-id', help='Get instance details nicely formatted', required=False, default=None)
parser.add_argument('-l','--list', help='Amount of instances per region (one or more)', required=False, default=None, action='store_true')
args = vars(parser.parse_args())

console = Console( )


def handler(signum, frame):
    """
    Handles ctrl-c on show_instances() for a clean exit.
    
    """

    console.log(":warning: Ctrl-C detected. Exiting lister..." , style="bold yellow")
    exit(2)

signal.signal(signal.SIGINT, handler)


def region_lister(profile: str) -> list:
    """
    List all regions from AWS instead of hardcoding them.

    Args:
        profile: AWS profile to be used.
    Return:
        List of regions.
    """
    session = boto3.Session(profile_name=profile, region_name="us-east-1")
    client = session.client("ec2")
    REGIONS = [region['RegionName'] for region in client.describe_regions()['Regions']]
    return REGIONS


def get_ec2(profile: str, region: str = None, REGIONS: list = None) -> object:
    """
    Return a boto3 ec2 session object.

    Args:
        profile: AWS profile to be used.
        region: AWS region to be used.
    Return:
        boto3 ec2 session object.
    """
    if region:
        if region not in REGIONS:
            console.log(f":warning: Region {region} is not valid. Exiting...", style="bold red")
            exit(1)
        session = boto3.Session(profile_name=profile, region_name=region)
    else:
        random_region = choice(REGIONS)
        session = boto3.Session(profile_name=profile, region_name=random_region)
        console.log(f":warning: No region defined. Using [bold underline white on black]{random_region}[/] as profile region.", style="bold yellow")

    return session.resource("ec2")


def lister(REGIONS: list = None) -> None:
    """
    List how many instances we have for each region.

    Args:
        None.
    Return:
        Nothing.
    """
    for region in REGIONS:
        with console.status(f"[bold green]Getting instances for[/] {region} ...", spinner="dots"):
            ec2 = get_ec2(profile=args.get("profile"), region=region)
            instances = list(ec2.instances.all())

            color = "white"
            style = "bold green"
            if not instances:
                color = "red"
                style = "bold red"

            msg = (
                f"Found [bold underline {color} on black]{len(instances)}[/] instances on" 
                f" region [bold underline white on black]{region}[/]"
            )
            console.log(msg, style=style)


def show_instance(ec2, instance_id) -> None:
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
        table = Table(show_header=True, header_style="bold magenta", show_lines=True)
        table.add_column("Attribute", style="white bold dim", width=30)
        table.add_column("Value", style="white dim")
        table.add_row("Instance ID", instance.id)
        table.add_row("Instance Type", instance.instance_type)
        table.add_row("Instance State", instance.state['Name'])
        table.add_row("Instance Launch Time", str(instance.launch_time))
        table.add_row("Instance Public IP", instance.public_ip_address)
        table.add_row("Instance Private IP", instance.private_ip_address)
        table.add_row("Instance Public DNS", instance.public_dns_name)
        table.add_row("Instance Private DNS", instance.private_dns_name)
        table.add_row("Instance Key Name", instance.key_name)
        table.add_row("Instance IAM Role", JSON(json.dumps(instance.iam_instance_profile)))
        table.add_row("Instance VPC ID", instance.vpc_id)
        table.add_row("Instance Subnet ID", instance.subnet_id)
        table.add_row("Instance Security Groups", JSON(json.dumps(instance.security_groups)))
        table.add_row("Instance Tags", JSON(json.dumps(instance.tags)))
    console.print(table)


def main(ec2) -> None:
    if args['filter_key'] and args['filter_value'] != None:
        filter = [{'Name': 'instance-state-name', 'Values': ['running']}]
        # allow multiple sets of filter keys and values
        for fk,fv in zip(args['filter_key'],args['filter_value']):
            if "," in fv:
                filter_list = [{'Name': fk, 'Values': fv.split(',')}]
            else:
                filter_list = [{'Name': fk, 'Values': [fv]}]
            filter += filter_list
    else:
        filter = [{'Name': 'instance-state-name', 'Values': ['running']}]

    ec2_list = []
    
    with console.status("[bold green]Listing instances...", spinner="dots"):
        for instance in ec2.instances.filter(
                Filters=filter):
            uptime = (datetime.datetime.now().astimezone() - instance.launch_time).days
            pub_ip = instance.public_ip_address

            # No need to check if private IPs are empty, since AWS will always assign a private IP to instances
            priv_ip_list = []
            for priv_ip in instance.network_interfaces_attribute:
                priv_ip_list.append(priv_ip['PrivateIpAddress'])
            name = "None"

            if pub_ip is None:
                pub_ip = "None"

            if instance.tags is None:
                tags = "None"
            else:
                for tags in instance.tags:
                    if tags["Key"] == "Name":
                        name = tags["Value"]

            ec2_list.append([instance.instance_id,name, pub_ip, ", ".join(priv_ip_list), str(uptime)+" Days"])

        ec2_table = Table(title="EC2 Instances")

        for header in ['Instance ID', 'Name', 'Public IP', 'Private IP', 'Uptime (days)']:
            ec2_table.add_column(header, justify="center", style="cyan", no_wrap=True)

        for row in ec2_list:
            ec2_table.add_row(*row)

    console.print(ec2_table)


if __name__ == "__main__":
    profile_name = args.get("profile")
    region_name = args.get("region")
    
    try:
        REGIONS = region_lister(profile=profile_name)
    except:
        console.log(f":warning: Profile {profile_name} is not valid. Exiting...", style="bold red")
        exit(1)
    ec2 = get_ec2(profile=profile_name, region=region_name, REGIONS=REGIONS)

    if args.get("list"):
        lister(REGIONS=REGIONS)

    elif args.get("instance_id"):
        show_instance(ec2, args.get("instance_id"))

    else:
        main(ec2)
