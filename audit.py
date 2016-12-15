#!/usr/bin/env python

from __future__ import print_function
from dateutil.parser import parse

import boto3
import ConfigParser
import datetime
import json
import logging
import re
import time
import urllib
import urllib2

### GLOBAL VARIABLES ###
config = ConfigParser.ConfigParser()
config.readfp(open(r'.config'))

SUMO_ENDPOINT = config.get('Default', 'sumo_endpoint')

# Set profile
boto3.setup_default_session(profile_name='cis_benchmarks')

logging.basicConfig(level=None)
logger = logging.getLogger(__name__)

now = datetime.datetime.utcnow().replace(microsecond=0)

### Handlers ###
def date_handler(obj):
    if hasattr(obj, 'isoformat'):
        return obj.isoformat()
    else:
        raise TypeError

def unused_credential_check(last_access):

    #global now
    last_access = re.sub(r'\+\d+:\d+', '', last_access)
    try:
        last_access = datetime.datetime.strptime(last_access, "%Y-%m-%dT%H:%M:%S")
    except Exception as e:
        print("error type", type(e))
        pass

    duration =  now - last_access

    if duration.days > 15:
        return True
    else:
        return False


def convert(input):
    """Covert from unicode to utf8"""
    if isinstance(input, dict):
        return {convert(key): convert(value) for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [convert(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input

def send_to_sumo(data):
    '''
    Sends log message to hosted collector
    '''

    data = json.dumps(data)

    print(urllib2.urlopen(SUMO_ENDPOINT, data).read())

### CIS AWS Benchmark Audit Checks ###
def get_user_info():
    """Get data for audit checks 1.1, 1.2, 1.3, 1.4, 1.12, 1.13, 1.15"""

    # report field names to be used in arrays
    fields = []

    logger.info('Establishing iam connection')
    try:
        iam = boto3.client('iam')
    except Exception as e:
        print(e)
    #iam = boto3.client('iam', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)


    try:
        report = iam.get_credential_report()

    except Exception, e:
        if re.search('(ReportNotPresent)', str(e)):
            print("Credential report not present, creating report")
        else:
            print(e)
        response = iam.generate_credential_report()
        time.sleep(1)
        report = iam.get_credential_report()

    report = convert(report)

    content = (report['Content'].splitlines(True))

    for index in range(len(content)):
        # Parse field names into fields
        if index is 0:
            fields = content[0].split(',')

        else:
            userInfo = {'benchmarkVersion': '1.0.0', 'eventType' : 'userInfo', 'timestamp' : str(now)}
            d = {}
            s = content[index].split(',')

            for index in range(len(fields)):
                d[fields[index]] = s[index]

            if (d['password_enabled'] == 'true'):
                if d['password_last_used'] == 'N/A':
                    #result = unused_credential_check(d['password_last_used'])
                    d['password_greater_than_90'] = 'N/A'
                else:
                    result = unused_credential_check(d['password_last_used'])
                    if result:
                        d['password_greater_than_90'] = 'True'
                    else:
                        d['password_greater_than_90'] = 'False'

            if (d["access_key_1_active"] == 'true'):
                if d['access_key_1_last_used_date'] == 'N/A':
                    d['access_key_1_greater_than_90'] = 'N/A'
                else:
                    result = unused_credential_check(d['access_key_1_last_used_date'])

                    if result:
                        d['access_key_1_greater_than_90'] = 'True'
                    else:
                        d['access_key_1_greater_than_90'] = 'False'

                if d['access_key_1_last_rotated'] == 'N/A':
                    d['access_key_1_rotated_within_90'] = 'N/A'
                else:
                    result = unused_credential_check(d['access_key_1_last_rotated'])

                    if result:
                        d['access_key_1_rotated_greater_than_90'] = 'True'
                    else:
                        d['access_key_1_rotated_greater_than_90'] = 'False'

            if (d["access_key_2_active"] == 'true'):
                if d['access_key_2_last_used_date'] == 'N/A':
                    d['access_key_2_greater_than_90'] = 'N/A'
                else:
                    result = unused_credential_check(d['access_key_2_last_used_date'])
                    if result:
                        d['access_key_2_greater_than_90'] = 'True'
                    else:
                        d['access_key_2_greater_than_90'] = 'False'

            if d['access_key_2_last_rotated'] == 'N/A':
                d['access_key_2_rotated_within_90'] = 'N/A'
            else:
                result = unused_credential_check(d['access_key_1_last_rotated'])

                if result:
                    d['access_key_2_rotated_greater_than_90'] = 'True'
                else:
                    d['access_key_2_rotated_greater_than_90'] = 'False'

            if not re.search('^<root_account>', s[0]):
                # Generate data for check 1.15
                try: policy = iam.list_user_policies(UserName=s[0])
                except Exception, e:
                    print(e)
                if not policy["PolicyNames"]:
                    d["AttachedPolicy"] = "False"
                else:
                    d["AttachedPolicy"] = "True"
            else:
                d["AttachedPolicy"] = "NA"

            userInfo['data'] = d
            send_to_sumo(userInfo)
            print(userInfo)

def get_account_info():
    """Get data for audit checks 1.5-1.11, 1.13"""
    d = {}

    iam = boto3.client('iam')
    #iam = boto3.client('iam',aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

    ### Generate data for audit checks 1.5-1.11 ###
    try: results = iam.get_account_password_policy()
    except Exception, e:
        if re.search('NoSuchEntity', str(e)):
            print("No Account Password Policy exists")
            results = str(e)
        else:
            print(e)
            results = ("Error")

    accountInfo = {'benchmarkVersion': '1.0.0', 'eventType': 'accountInfo', 'timestamp': str(now)}

    if results == "NoSuchEntity" or results == "Error":
        print(results)
        d["PasswordPolicy"] = "No Account Password Policy exists"
    else:
        results = convert(results)


        # Key Value pairs not present in Password Policy until selected for the first time
        if not "MaxPasswordAge" in results["PasswordPolicy"]:
            results["PasswordPolicy"]["MaxPasswordAge"] = "False"
        if not "RequireUppercaseCharacters" in results["PasswordPolicy"]:
            results["PasswordPolicy"]["RequireUppercaseCharacters"] = "False"
        if not "RequireLowercaseCharacters" in results["PasswordPolicy"]:
            results["PasswordPolicy"]["RequireLowercaseCharacters"] = "False"
        if not "HardExpiry" in results["PasswordPolicy"]:
            results["PasswordPolicy"]["HardExpiry"] = "False"
        if not "RequireNumbers" in results["PasswordPolicy"]:
            results["PasswordPolicy"]["RequireNumbers"] = "False"
        if not "ExpirePasswords" in results["PasswordPolicy"]:
            results["PasswordPolicy"]["ExpirePasswords"] = "False"
        if not "RequireSymbols" in results["PasswordPolicy"]:
            results["PasswordPolicy"]["RequireSymbols"] = "False"
        if not "AllowUsersToChangePassword" in results["PasswordPolicy"]:
            results["PasswordPolicy"]["AllowUsersToChangePassword"] = "False"
        if not "PasswordReusePrevention" in results["PasswordPolicy"]:
            results["PasswordPolicy"]["PasswordReusePrevention"] = "False"
        if not "MinimumPasswordLength" in results["PasswordPolicy"]:
            results["PasswordPolicy"]["MinimumPasswordLength"] = "False"

        d["PasswordPolicy"] = results["PasswordPolicy"]
    print(d)


    '''Generate data for audit check 1.13'''

    try: summary = iam.get_account_summary()
    except Exception, e:
        print(e)

    if summary["SummaryMap"]["AccountMFAEnabled"] == '1':
        d["AccountMFAEnabled"] = "True"
    else:
        d["AccountMFAEnabled"] = "False"

    accountInfo['data'] = d
    send_to_sumo(accountInfo)

def get_cloudtrail():
    """Get data for audit checks 2.1-2.8"""

    #cloudtrail = boto3.client('cloudtrail')
    #cloudtrail = boto3.client('cloudtrail', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

    client = boto3.client('ec2')
    #regions = [region['RegionName'] for region in client.describe_regions()['Regions']])
    for region in client.describe_regions():
        print(region)

    #d = {}

    #trails = cloudtrail.describe_trails(trailNameList=[], includeShadowTrails=True)
    #trails2 = cloudtrail.describe_trails()

    #trailList = trails2["trailList"]

    #print("\n\n",trails,"\n\n")
    #print("\n\n",trails2,"\n\n")

    '''
    for index in range(len(trailList)):
        print(trailList[index])

    
    ### Generate data for check 2.1, 2.2 ###
    d["IsMultiRegionTrail"] = trails["trailList"][0]["IsMultiRegionTrail"]
    d["LogFileValidationEnabled"] = trails["trailList"][0]["LogFileValidationEnabled"]

    
    ### Generate data for check 2.3 ###
    bucket = trails['trailList'][0]['S3BucketName']

    s3 = boto3.client('s3', profile_name=PROFILE_NAME)
    #s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

    bucket_acl = s3.get_bucket_acl(Bucket=bucket)
    
    d["AllUsersGrantedPrivileges"] = False
    d["AuthenticatedUsersGrantedPrivileges"] = False

    for item in bucket_acl['Grants']:
        if re.search('.*AllUsers.*', str(item)):
            d["AllUsersGrantedPrivileges"] = True
        
        if re.search('.*AuthenticatedUsers.*', str(item)):
            d["AuthenticatedUsersGrantedPrivileges"] = True

    bucket_policy = s3.get_bucket_policy(Bucket=bucket)
    
    policy = bucket_policy["Policy"]
    policy = policy.encode()
    policy = json.loads(policy)
    
    
    statement = policy["Statement"]
    
    d["BucketViolation"] = None
    
    for index in range(len(statement)):
        if d["BucketViolation"] == True:
            break
        elif (statement[index]["Principal"] == "*") and (statement[index]["Effect"] == "Allow"):
            d["BucketViolation"] = True
        else:
            d["BucketViolation"] = False
    
    ### Generate data for check 2.4 ###
    #print(trails2)
    '''

def main():

    get_user_info()
    get_account_info()
    #get_cloudtrail()

if __name__ == "__main__":
    main()

