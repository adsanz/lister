# EC2 instance lister with filtering and formatting

This script can be used to get instances and filtering them, use `lister.py -h` to see how to execute the script.

The script will retrieve the public IP, private IP, name and instance ID of all running instances on a especific region.

You will require a profile with access to ec2 listing.


Help command: 

```
usage: lister.py [-h] [-r REGION] -p PROFILE [-fk [FILTER_KEY [FILTER_KEY ...]]] [-fv [FILTER_VALUE [FILTER_VALUE ...]]] [-l] [-i INSTANCE_ID]

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

optional arguments:
  -h, --help            show this help message and exit
  -r REGION, --region REGION
                        Region to be used for ec2 listing
  -p PROFILE, --profile PROFILE
                        Profile to authenticate
  -fk [FILTER_KEY [FILTER_KEY ...]], --filter_key [FILTER_KEY [FILTER_KEY ...]]
                        Key used for filtering
  -fv [FILTER_VALUE [FILTER_VALUE ...]], --filter_value [FILTER_VALUE [FILTER_VALUE ...]]
                        Value used for filtering (one or more)
  -l, --list            Ammount of instances per region (one or more)
  -i INSTANCE_ID, --instance-id INSTANCE_ID
                        Get instance details nicely formated
```


## Output

**Added on V1**

I'm using [Rich](https://github.com/Textualize/rich) to format tables and output so it's easier on the human eye :) 

### Nice tracebacks

Set `NICE_TRACEBACK = True` if you want nicer tracebacks, useful for debugging. It's disabled by default.

By AdSanz