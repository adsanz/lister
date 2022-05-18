# EC2 instance lister with filtering and formatting

This script can be used to get instances and filtering them, use `lister.py -h` to see how to execute the script.

The script will retrieve the public IP, private IP, name and instance ID of all running instances on a especific region.

You will require a profile with access to ec2 listing.

Requires:
- boto3
- tabulate
- profiles with access to ec2 read capabilities

By AdSanz @ MrMilú