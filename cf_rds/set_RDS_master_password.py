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

#
# GLOBAL VARIABLES
#


table_keyid = 'dbid'


def encrypt_password(key_id=None, password=None):
    """
    Function to encrypt the password with KMS
    :param: key_id: KMS Key Id
    :param: password to encrypt
    :return: String password in base64
    """
    client = boto3.client('kms')
    try:
        encrypted = client.encrypt(
            KeyId=key_id,
            Plaintext=password
        )
        encrypted_b64 = base64.b64encode(encrypted['CiphertextBlob'])
        return {'encrypted': True, 'password': encrypted_b64}
    except Exception as e:
        return {'encrypted': False, 'Reason': e}


def generate_random_string(string_length=20, underscore=False):
    """
    Generates a random string sent back to CF
    :param string_length: Length of the string in number of characters
    :return: String of the string
    """
    generated_string = ''
    char_set = string.ascii_uppercase + string.ascii_lowercase + string.digits + '-'
    while '-' not in generated_string or \
          generated_string.endswith('-') or \
          generated_string.startswith('-'):
        generated_string = ''.join(random.sample(char_set * 6, int(string_length)))
    if underscore:
        return generated_string.replace('-', '_')
    return generated_string


def add_master_creds(table_name,
                     stack_name,
                     key_id):
    """
    Create Master function
    """
    username = generate_random_string(10, True)
    password = generate_random_string(21)
    encrypted_password = encrypt_password(key_id, password)
    if encrypted_password['encrypted']:
        return put_password_in_dynamodb(
            table_name,
            stack_name,
            username,
            encrypted_password['password']
        )
    return encrypted_password


def put_password_in_dynamodb(table_name,
                             stack_name,
                             user_name,
                             b64_encrypted_password,
                             update=False):
    """
    Function to store the b64 password in DynamoDB
    :param table_name: Name of the table
    :param stack_name: Name of the RDS Stack
    :param user_name: Name of the master user for RDS Instance
    :param password: string of the base64 encrypted password for the RDS Instance
    :param attribute_name: String of the unique attribute name of the DynDB Table
    :param update: Boolean() to determine whether or not the table should be updated
    """

    hash_string = hashlib.sha256(stack_name).hexdigest().strip()
    client = boto3.resource('dynamodb')
    table = client.Table(table_name)

    try:
        response = table.query(
            KeyConditionExpression=Key(table_keyid).eq(hash_string)
        )
    except Exception as e:
        return {'added': False, 'Reason': e}

    if response['Count'] != 0 and not update:
        return {'added': False, 'Reason': "Entry already exists in Dynamo DB table"}

    elif (response['Count'] != 0 and update) or \
         (response['Count'] == 0):
        print response['Count']
        print update
        try:
            response = table.put_item(
                Item={
                    table_keyid : hash_string,
                    'user_name' : user_name,
                    'b64_password': b64_encrypted_password
                }
            )
            return {'added': True, 'Reason': 'Successfully Added to DynDB'}
        except Exception as e:
            return {'added': False, 'Reason': e}


def delete_from_dyndb(table_name,
                      stack_name):
    """
    Function to store the b64 password in DynamoDB
    :param table_name: Name of the table
    :param stack_name: Name of the RDS Stack
    :param update: Boolean() to determine whether or not the table should be updated
    """

    hash_string = hashlib.sha256(stack_name).hexdigest().strip()
    client = boto3.resource('dynamodb')
    table = client.Table(table_name)

    try:
        response = table.query(
            KeyConditionExpression=Key(table_keyid).eq(hash_string)
        )
    except Exception as e:
        return {'deleted': False, 'Reason': e}

    if response['Count'] != 1:
        return {'deleted': True, 'Reason': "Entry doesnt exist - no delete required"}

    elif response['Count'] == 1:
        try:
            response = table.delete_item(
                Key={
                    table_keyid : hash_string
                }
            )
            return {'deleted': True, 'Reason': 'Successfully Deleted from DynDB'}
        except Exception as e:
            return {'deleted': False, 'Reason': e}

# LAMBDA SPECIFIC


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

    if not check_event_keys(event, ['TableName', 'StackName']):
        return send_response(
            event,
            response,
            status='FAILED',
            reason='Function parameters missing'
        )

    if event['RequestType'] == 'Update':
        return send_response(event, response)

    if event['RequestType'] == 'Create':
        creds = add_master_creds(
            event['ResourceProperties']['TableName'],
            event['ResourceProperties']['StackName'],
            event['ResourceProperties']['KeyId']
        )
        if not creds['added']:
            response['Status'] = 'FAILED'
        response['Reason'] = creds['Reason']

    elif event['RequestType'] == 'Delete':
        deleted = delete_from_dyndb(
            event['ResourceProperties']['TableName'],
            event['ResourceProperties']['StackName']
        )
        if not deleted['deleted']:
            response['Status'] = 'FAILED'
            response['Reason'] = deleted['Reason']
        return send_response(event, response)

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


def check_event_keys(event, keys_list):
    """
    Function to check all the event keys are present for the function to work
    """
    for key in keys_list:
        if not key in event['ResourceProperties'].keys():
            return False
    return True



# FOR CLI USAGE


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Script to autogenerate username and password"
                                     " for a stack_name and store in DynDB")
    parser.add_argument('--stack-name', '-s', help="Name of the stack", required=True)
    parser.add_argument('--key-id', '-k', help="KMS Key Id", required=True)
    parser.add_argument('--table-name', '-t', help="Name of the DynamoDB Table", required=True)
    parser.add_argument('--delete', help="Test the delete function", required=False, action='store_true')

    args = parser.parse_args()
    if not args.delete:
        creds = add_master_creds(args.table_name, args.stack_name, args.key_id)
        print(creds['Reason'])
    else:
        deletion = delete_from_dyndb(args.table_name, args.stack_name)
        print deletion['Reason']
