#!/usr/bin/env python3
""" Read the aws configuration and 
    use those credentials to save
    policy permissions to files

"""

import pprint
import datetime
import json
import boto3
import os
import configparser
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('-e','--exclude', action='append', help='Exclude Items', required=False)


config = configparser.ConfigParser()
config.read('/root/.aws/config')
pp = pprint.PrettyPrinter(width=1)

# Root path to save the permissions to

save_dir = '/etc/aws/aws-permissions'


# Class describes basic information about an AWS policy

class awspolicy():
    def __init__(self):
        self.PolicyName = None
        self.PolicyArn = None
        self.DefaultVersionId = None
        self.PolicyDocument = None


# Get the AWS profiles from ~/.aws/config
# Returns a list of profiles available
def get_aws_profiles(exclusions):
    profiles = list()
    for env in config.sections():
        env_only = env.split()[1]
        if env_only not in exclusions:
            profiles.append(env_only)
        else:
            print("excluded %s" % env_only)
    return profiles


# DateTime handler for json.dump

def datetime_handler(x):
    if isinstance(x, datetime.datetime):
        return x.isoformat()
    raise TypeError("Unknown type")


# Get IAM policies based on the available environments
# Return a dictionary based on the profile with a list of 
# awspolicy class objects

def get_aws_iam_policies(exclusions):
    policies = {}
    for profile in get_aws_profiles(exclusions):
        boto3.setup_default_session(profile_name=profile)
        iam = boto3.client('iam')
        policy_list = iam.list_policies(Scope='Local')
        pols = list()
        for p in policy_list['Policies']:
            name = p['PolicyName']
            arn = p['Arn']
            version = p['DefaultVersionId']
            pol = awspolicy()
            pol.PolicyName = name
            pol.PolicyArn = arn
            pol.DefaultVersionId = version
            pols.append(pol)
        policies[profile] = pols
    return policies


# Using a policy dict returned by get_aws_iam_policies
# Get the policy details (permissions json)
# Assigns them to the same awspolicy object
# Saves a file with the policy name in a directory
# named based on the profile

def get_policy_details(policydict):
    for env in policydict:
        path = os.path.join(save_dir, env)
        if not os.path.exists(path):
            os.mkdir(path)
            
        boto3.setup_default_session(profile_name=env)
        iam = boto3.client('iam')
        for pol in policydict[env]:
            arn = pol.PolicyArn
            version = pol.DefaultVersionId
            perms = iam.get_policy_version(PolicyArn=arn, VersionId=version)
            pol.PolicyDocument = perms['PolicyVersion']
            save_file = os.path.join(path,pol.PolicyName)
            with open(save_file, 'w') as f:
                json.dump(pol.__dict__, f, default=datetime_handler, sort_keys=True, indent=4)
        

if __name__ == "__main__":
    args = parser.parse_args()
    exclusions = args.exclude
    all_envs = get_aws_iam_policies(exclusions)
    get_policy_details(all_envs)