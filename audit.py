#!/usr/bin/env python

from __future__ import print_function

import time
import re
import json
import urllib
import urllib2
import boto3

### GLOBAL VARIABLES ###
AWS_ACCESS_KEY_ID = 'AKIAIPSSPRW4UD6QOYXQ'
AWS_SECRET_ACCESS_KEY = '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'

sumoEndpoint = 'https://endpoint2.collection.sumologic.com/receiver/v1/http/ZaVnC4dhaV2RDfCeyDY1DfHSpTHcR3mEEvOxQunXfTj2AWVjhQG9Q3PwxE7h1uzNRhRH2By271B9kFuVIeK4f8B9y-v0-fNV2wTPYX-5KjJYnyNELgQePw=='

### Handlers ###
def date_handler(obj):
    if hasattr(obj, 'isoformat'):
        return obj.isoformat()
    else:
        raise TypeError

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
    """Sends log message to hosted collector"""
    data = json.dumps(data)
    print(urllib2.urlopen(sumoEndpoint, data).read())

### CIS AWS Benchmark Audit Checks ###
def get_user_info():
    '''Get data for audit checks 1.1, 1.2, 1.3, 1.4, 1.12, 1.13, 1.15'''
    
    fields = []
    
    iam = boto3.client('iam',
                    aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
                    )

    try: report = iam.get_credential_report()
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
        #Parse field names into fields
        if index is 0:
            fields = content[0].split(',')

        else:
            userInfo = {'benchmarkVersion': '1.0.0', 'eventType' : 'userInfo'}
            d = {}
            s = content[index].split(',')

            for index in range(1, 22):
                d[fields[index]] = s[index]

            if not re.search('^<root_account>', s[0]):
                ### Generate data for check 1.15 ###
                try: policy = iam.list_user_policies(UserName=s[0])
                except Exception, e:
                    print(e)
                if not policy["PolicyNames"]:
                    d["AttachedPolicy"] = "False"
                else:
                    d["AttachedPolicy"] = "True"
            else:
                d["AttachedPolicy"] = "NA"

            userInfo[s[0]] = d
            send_to_sumo(userInfo)

def get_policy():
    '''Get data for audit checks 1.5-1.11, 1.13'''
    d = {}
    
    iam = boto3.client('iam',
                    aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
                    )

    ### Generate data for audit checks 1.5-1.11 ###
    try: results = iam.get_account_password_policy()
    except Exception, e:
        if re.search('NoSuchEntity', str(e)):
            print("No Account Password Policy exists")
        else:
            print(e)

    results = convert(results)

    d["PasswordPolicy"] = (results["PasswordPolicy"])

    ### Generate data for audit check 1.13 ###
    try: summary = iam.get_account_summary()
    except Exception, e:
        print(e)

    d["AcountMFAEnabled"] = summary["SummaryMap"]["AccountMFAEnabled"]

    send_to_sumo(d)

def get_cloudtrail():
    '''Get data for audit checks 2.1-2.8'''
    
    cloudtrail = boto3.client('cloudtrail',
                    aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
                    )

    d = {}

    trails = cloudtrail.describe_trails(trailNameList=[], includeShadowTrails=True)
    trails2 = cloudtrail.describe_trails()
    trailList = trails2["trailList"]
    for index in range(len(trailList)):
        print(trailList[index])

    
    ### Generate data for check 2.1, 2.2 ###
    d["IsMultiRegionTrail"] = trails["trailList"][0]["IsMultiRegionTrail"]
    d["LogFileValidationEnabled"] = trails["trailList"][0]["LogFileValidationEnabled"]

    
    ### Generate data for check 2.3 ###
    bucket = trails['trailList'][0]['S3BucketName']

    s3 = boto3.client('s3',
                    aws_access_key_id=AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
                    )

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

def lambda_handler(event, context):
    get_user_info()
    get_policy()
    get_cloudtrail()
