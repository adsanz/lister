# Lister
![Tests](https://github.com/adsanz/lister/actions/workflows/github-actions-test.yaml/badge.svg)


A python utility to gather info from EC2 instances faster than from AWS web console.
- List all instances on a region
- Find out in which regions you have instances
- Filter instance with tags

## Install

Right now we are using poetry, a nice packaging and dependency management tool. Refer to the docs for advance usage, for now:

1. Install poetry (as per they [documentation](https://python-poetry.org/docs/#installation))
2. Run `poetry install`
3. Run `poetry shell` 

That will install on your `~/.local/bin` the lister script.

### Requirements

You will require an [AWS named profile](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html) with enough permissions to get regions and read instance details. 

Aditionally you can start [localstack](https://github.com/localstack/localstack) and work with your own local aws ec2 instance. This is for testing / developing (set `-ls` to enable the localstack custom endpoint.)

## Usage

Use `lister -h` to see how it works

By AdSanz
