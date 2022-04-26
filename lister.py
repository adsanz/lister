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

In case you don't know the regions, these are the avilable ones:

---------------------------------------------------------------------------------
|                                DescribeRegions                                |
+-------------------------------------------------------------------------------+
||                                   Regions                                   ||
|+-----------------------------------+-----------------------+-----------------+|
||             Endpoint              |      OptInStatus      |   RegionName    ||
|+-----------------------------------+-----------------------+-----------------+|
||  ec2.eu-north-1.amazonaws.com     |  opt-in-not-required  |  eu-north-1     ||
||  ec2.ap-south-1.amazonaws.com     |  opt-in-not-required  |  ap-south-1     ||
||  ec2.eu-west-3.amazonaws.com      |  opt-in-not-required  |  eu-west-3      ||
||  ec2.eu-west-2.amazonaws.com      |  opt-in-not-required  |  eu-west-2      ||
||  ec2.eu-west-1.amazonaws.com      |  opt-in-not-required  |  eu-west-1      ||
||  ec2.ap-northeast-3.amazonaws.com |  opt-in-not-required  |  ap-northeast-3 ||
||  ec2.ap-northeast-2.amazonaws.com |  opt-in-not-required  |  ap-northeast-2 ||
||  ec2.ap-northeast-1.amazonaws.com |  opt-in-not-required  |  ap-northeast-1 ||
||  ec2.sa-east-1.amazonaws.com      |  opt-in-not-required  |  sa-east-1      ||
||  ec2.ca-central-1.amazonaws.com   |  opt-in-not-required  |  ca-central-1   ||
||  ec2.ap-southeast-1.amazonaws.com |  opt-in-not-required  |  ap-southeast-1 ||
||  ec2.ap-southeast-2.amazonaws.com |  opt-in-not-required  |  ap-southeast-2 ||
||  ec2.eu-central-1.amazonaws.com   |  opt-in-not-required  |  eu-central-1   ||
||  ec2.us-east-1.amazonaws.com      |  opt-in-not-required  |  us-east-1      ||
||  ec2.us-east-2.amazonaws.com      |  opt-in-not-required  |  us-east-2      ||
||  ec2.us-west-1.amazonaws.com      |  opt-in-not-required  |  us-west-1      ||
||  ec2.us-west-2.amazonaws.com      |  opt-in-not-required  |  us-west-2      ||
|+-----------------------------------+-----------------------+-----------------+|

""",formatter_class=RawTextHelpFormatter)
parser.add_argument('-r','--region', help='Region to be used for ec2 listing', required=False, default=None)
parser.add_argument('-p','--profile', help='Profile to authenticate', required=True)
parser.add_argument('-fk','--filter_key', help='Key used for filtering', required=False, default=None)
parser.add_argument('-fv','--filter_value', help='Value used for filtering', required=False, default=None)
args = vars(parser.parse_args())

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
    name = "None"
    if pub_ip == None:
        pub_ip = "None"
    for tags in instance.tags:
        if tags["Key"] == "Name":
            name = tags["Value"]
    ec2_list.append([instance.instance_id,name, pub_ip])
    
print(
    tabulate(ec2_list, 
    headers=['Instance ID','Name','Public IP'])
)