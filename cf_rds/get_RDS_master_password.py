#!/usr/bin/env python

"""

Lambda function to fetch from DynamoDb the Master user and password of an RDS Instance

"""
import base64
import json
import random
import string
import hashlib
import uuid
import httplib
import urlparse
import boto3
from boto3.dynamodb.conditions import Key, Attr


def get_creds_from_dyndb(table_name,
                         stack_name,
                         attribute_name):
    """
    Function to store the b64 password in DynamoDB
    :param table_name: Name of the table
    :param stack_name: Name of the RDS Stack
    :param attribute_name: String of the unique attribute name of the DynDB Table
    """

    hash_string = hashlib.sha256(stack_name).hexdigest().strip()
    client = boto3.resource('dynamodb')
    table = client.Table(table_name)

    try:
        response = table.query(
            KeyConditionExpression=Key(attribute_name).eq(hash_string)
        )
    except Exception as e:
        return {'found': False, 'Reason': e}

    if (response['Count'] != 1):
        return {'found': False, 'Reason': 'No record found for that stack'}
    return {'found': True, 'creds': response['Items']}


def get_master_creds(table_name,
                     stack_name):
    """
    Master function
    """
    creds = get_creds_from_dyndb(table_name, stack_name, 'rds_id')

    if not creds['found']:
        return {'obtained': False, 'Reason': creds['Reason']}

    password_b64 = creds['creds'][0]['b64_password']
    username = creds['creds'][0]['user_name']
    password = decrypt_password(password_b64)
    if not password['decrypted']:
        return {'obtained': False, 'Reason': password['Reason']}

    data = {
        'username': username,
        'password': password['password']
    }
    return {'obtained' : True, 'Reason': 'Successfully retrieved username and password', 'creds': data}


def lambda_handler(event, context):
    """
    AWS Lambda function handler
    :param event: Lambda event data
    :param context: Lambda defined context params
    :return: Calls for send_response when the code could be executed without problem
    """

    response = {
    'StackId': event['StackId'],
    'RequestId': event['RequestId'],
    'LogicalResourceId': event['LogicalResourceId'],
    'Status': 'SUCCESS'
    }

    if 'PhysicalResourceId' in event:
        response['PhysicalResourceId'] = event['PhysicalResourceId']
    else:
        response['PhysicalResourceId'] = str(uuid.uuid4())

    # There is nothing to do for a delete or update request

    if (event['RequestType'] == 'Delete') or \
       (event['RequestType'] == 'Update'):
        return send_response(event, response)


    for key in ['StackName', 'TableName']:
        if not key in event['ResourceProperties'].keys():
            return send_response(
                event,
                response,
                status='FAILED',
                reason='The properties TableName and StackName must be present'
            )

    creds = get_master_creds(
        event['ResourceProperties']['TableName'],
        event['ResourceProperties']['StackName'],
        )
    if not creds['obtained']:
        response['Status'] = 'FAILED'
    else:
        response['Data'] = creds['creds']
    response['Reason'] = creds['Reason']
    return send_response(
        event,
        response
    )


# NEVER CHANGE THE SEND RESPONSE FUNCTION

def send_response(request, response, status=None, reason=None):
    """
    Send our response to the pre-signed URL supplied by CloudFormation
    If no ResponseURL is found in the request, there is no place to send a
    response. This may be the case if the supplied event was for testing.
    :return: response object
    """

    if status is not None:
        response['Status'] = status

    if reason is not None:
        response['Reason'] = reason

    if 'ResponseURL' in request and request['ResponseURL']:
        try:
            url = urlparse.urlparse(request['ResponseURL'])
            body = json.dumps(response)
            https = httplib.HTTPSConnection(url.hostname)
            https.request('PUT', url.path + '?' + url.query, body)
        except:
            print("Failed to send the response to the provdided URL")
    return response


def decrypt_password(password_b64):
    """
    Function to encrypt the password with KMS
    :param password_b64: b64 string of the encrypted password
    """
    password_encrypted = base64.b64decode(password_b64)
    client = boto3.client('kms')
    try:
        password = client.decrypt(CiphertextBlob=password_encrypted)
        return {'decrypted': True, 'password': password['Plaintext']}
    except Exception as e:
        return {'descripted': False, 'Reason': e}

# FOR CLI TESTING


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description="Script to autogenerate username and password"
        " for a stack_name and store in DynDB"
    )
    parser.add_argument('--stack-name', '-s', help="Name of the stack", required=True)
    parser.add_argument('--table-name', '-t', help="Name of the DynamoDB Table", required=True)

    args = parser.parse_args()
    creds = get_master_creds(args.table_name, args.stack_name)
    print(creds['Reason'])
