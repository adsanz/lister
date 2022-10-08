#!/usr/bin/python3

import json
import datetime
import argparse

import boto3
from rich.json import JSON
from rich.console import Console
from rich.table import Table


REGIONS = (
    'us-west-1',
    'us-west-2',
    'us-east-1',
    'us-east-2',
    'eu-west-1',
    'eu-west-2',
    'eu-west-3',
    'eu-central-1',
    'eu-north-1',
    'ap-south-1',
    'ap-southeast-1',
    'ap-northeast-1',
    'ap-northeast-2',
    'ap-northeast-3',
    'ap-southeast-1',
    'ap-southeast-2',
    'sa-east-1',
    'ca-central-1',
)


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

""", formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-r','--region', help='Region to be used for ec2 listing', required=False, default=None)
parser.add_argument('-p','--profile', help='Profile to authenticate', required=True)
parser.add_argument('-fk','--filter_key', help='Key used for filtering', required=False, default=None, nargs='*')
parser.add_argument('-fv','--filter_value', help='Value used for filtering (one or more)', required=False, default=None, nargs='*')
parser.add_argument('-i','--instance-id', help='Get instance details nicely formatted', required=False, default=None)
parser.add_argument('-l','--list', help='Amount of instances per region (one or more)', required=False, default=None, action='store_true')
args = vars(parser.parse_args())

console = Console()


def lister() -> None:
    """
    List how many instances we have for each region.

    Args:
        None.
    Return:
        Nothing.
    """
    for region in REGIONS:
        session = boto3.session.Session(profile_name=args.get("profile"), region_name=region)

        with console.status(f"[bold green]Getting instances for[/] {region} ...", spinner="dots"):
            ec2 = session.resource('ec2')
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


def instance(ec2):
    with console.status("[bold green]Getting instances...", spinner="dots"):
        instance = ec2.Instance(args['instance_details'])
        table = Table(show_header=True, header_style="bold magenta", show_lines=True)
        table.add_column("Attribute", style="white bold dim", width=20)
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
        table.add_row("Instance IAM Role", instance.iam_instance_profile)
        table.add_row("Instance VPC ID", instance.vpc_id)
        table.add_row("Instance Subnet ID", instance.subnet_id)
        table.add_row("Instance Security Groups", JSON(json.dumps(instance.security_groups)))
        table.add_row("Instance Tags", JSON(json.dumps(instance.tags)))
    console.print(table)


def main():
    if args['region'] != None:
        session = boto3.session.Session(profile_name=args['profile'], region_name=args['region'])
    else:
        session = boto3.session.Session(profile_name=args['profile'])

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
    
    ec2 = session.resource('ec2')
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
    if args.get("list"):
        lister()
    else:
        main()
