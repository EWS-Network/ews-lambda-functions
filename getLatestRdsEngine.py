#!/usr/bin/env python
"""
Lambda script to get all Subnets within a VPC sorted on tag Usage
"""
from __future__ import print_function
import boto3
import uuid
import httplib
import urlparse
import json


def get_default_engine_version(engine='mysql'):
    """
    :param engine: DB Engine
    """
    client = boto3.resource('rds')
    r_version = client.describe_db_engine_versions(Engine=engine,
                                                   DefaultOnly=True)
    return r_version['DBEngineVersions'][0]['EngineVersion']


def send_response(request, response, status=None, reason=None):
    """ Send our response to the pre-signed URL supplied by CloudFormation
    If no ResponseURL is found in the request, there is no place to send a
    response. This may be the case if the supplied event was for testing.
    :param request: the event
    :param reason: A string to describe the reason of the status
    :param status: SUCCESS / FAILED
    :param response: response data of the CF Template
    """

    if status is not None:
        response['Status'] = status

    if reason is not None:
        response['Reason'] = reason

    if 'ResponseURL' in request and request['ResponseURL']:
        url = urlparse.urlparse(request['ResponseURL'])
        body = json.dumps(response)
        https = httplib.HTTPSConnection(url.hostname)
        https.request('PUT', url.path + '?' + url.query, body)

    return response


def lambda_handler(event, context):
    """
    Handler function for AWS Lambda
    :param event: Lambda event variables
    :param context: Lambda context variables
    :return: response message to the CloudFormation service
    """

    response = {
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Status': 'SUCCESS'
    }
    # PhysicalResourceId is meaningless here, but CloudFormation requires it
    if 'PhysicalResourceId' in event:
        response['PhysicalResourceId'] = event['PhysicalResourceId']
    else:
        response['PhysicalResourceId'] = str(uuid.uuid4())

    if 'Engine' not in event['ResourceProperties'].keys():
        response['Status'] = 'FAILED'
        response['Reason'] = 'Missing VpcId in Resource Properties'
        return send_response(event, response)
    # There is nothing to do for a delete request
    if event['RequestType'] == 'Delete':
        return send_response(event, response)
    else:
        response['Data'] = {}
        version = get_default_engine_version(event['ResourceProperties']['Engine'])
        response['Data']['Version'] = version
        response['Reason'] = "Version for %s is %s" % (event['ResourceProperties']['Engine'],
                                                       version)
    return send_response(event, response)
