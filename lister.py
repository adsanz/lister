#!/usr/bin/python3

import boto3
import argparse
from argparse import RawTextHelpFormatter
from tabulate import tabulate

parser = argparse.ArgumentParser(description="""
This script will list your ec2 instance with a given profile.
You may also define a region (if not configured on the profile this is required), and you can filter. A few examples:
- Get all instances on the default profile region that has the tag "env" on value "beta"
  lister.py -p leo -fk "tag:env" -fv beta

- Get all instances on the default profile region
  lister.py -p leo

- Get all instances on region 'us-west-1' with profile leo and tag "env" on value "prod"
  lister.py -p leo -r us-west-1 -fk "tag:env" -fv beta

Aditionally, you can list how many instances per region you have in case you don't know which region you are searching for
after this, you can filter adding the region you found instances for

- Find out how many instances per region you have
  lister.py -p leo -l

""",formatter_class=RawTextHelpFormatter)
parser.add_argument('-r','--region', help='Region to be used for ec2 listing', required=False, default=None)
parser.add_argument('-p','--profile', help='Profile to authenticate', required=True)
parser.add_argument('-fk','--filter_key', help='Key used for filtering', required=False, default=None)
parser.add_argument('-fv','--filter_value', help='Value used for filtering', required=False, default=None)
parser.add_argument('-l','--list', help='Ammount of instances per region', required=False, default=None, action='store_true')
args = vars(parser.parse_args())

def lister():
    if args['list'] != None:
        regions = ['us-west-1', 'us-west-2', 'us-east-1', 'us-east-2', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1', 'ap-south-1', 'ap-southeast-1', 'ap-northeast-1', 'ap-northeast-2',
        'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'sa-east-1', 'ca-central-1']
        for region in regions:
            instances = 0
            session = boto3.session.Session(profile_name=args['profile'], region_name=region)
            ec2 = session.resource('ec2')
            for instance in ec2.instances.all():
                instances = instances+1
            if instances != 0:
                print("Found {} instances on region {}".format(instances,region))

def main():
    if args['region'] != None:
        session = boto3.session.Session(profile_name=args['profile'], region_name=args['region'])
    else:
        session = boto3.session.Session(profile_name=args['profile'])

    if args['filter_key'] and args['filter_value'] != None:
        filter = [{'Name': 'instance-state-name', 'Values': ['running']},{'Name': args['filter_key'], 'Values': [args['filter_value']]}]
    else:
        filter = [{'Name': 'instance-state-name', 'Values': ['running']}]

    ec2_list = []

    ec2 = session.resource('ec2')
    for instance in ec2.instances.filter(
            Filters=filter):
        pub_ip = instance.public_ip_address
        # No need to check if priv IP are empty, since AWS will always assign a private IP to instances
        priv_ip_list = []
        for priv_ip in instance.network_interfaces_attribute:
            priv_ip_list.append(priv_ip['PrivateIpAddress'])
        name = "None"
        if pub_ip == None:
            pub_ip = "None"
        if instance.tags == None:
            tags = "None"
        else:
            for tags in instance.tags:
                if tags["Key"] == "Name":
                    name = tags["Value"]

        ec2_list.append([instance.instance_id,name, pub_ip, ", ".join(priv_ip_list)])
        
    print(
        tabulate(ec2_list, 
        headers=['Instance ID','Name','Public IP', 'Private IP'])
    )

if args['list'] != None:
    lister()
else:
    main()