#!/usr/bin/env python

import os
import sys
import uuid
import boto3
import string
import random
import argparse


def store_secure_string(name, value, key_id):
    """
    :param name: Name of the SSM Key
    :param value: Value of the SSM Key
    :param key_id: KMS Key ID
    """

    client = boto3.client('ssm')

    try:
        response = client.put_parameter(
            Name=name,
            Value=value,
            Type='SecureString',
            KeyId=key_id,
            Overwrite=False
        )
        return (True, "")
    except Exception as e:
        return (False, e)


def lambda_handler(event, context):
    """
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

    if not check_event_keys(event, ['StackName', 'KeyId']):
        return send_response(
            event,
            response,
            status='FAILED',
            reason='Function parameters missing'
        )
    username_key = event['ResourceProperties']['StackName'] + '-dbusername'
    password_key = event['ResourceProperties']['StackName'] + '-dbpassword'
    username = generate_random_string(8)
    password = generate_random_string(16)

    key_id = event['ResourceProperties']['KeyId']

    set_1 = store_secure_string(username_key, username, key_id)
    set_2 = store_secure_string(password_key, password, key_id)

    if not (set_1[0] and set_2[0]):
        return send_response(
            event,
            response,
            status='FAILED',
            reason="%s - %s" % (set_1[1], set_2[1])
        )
    reponse['Data']={
            username_key: username,
            password_key: password
    }
    return send_response(
        event,
        response,
        reason="Successfully added user and password in SSM"
    )


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


if __name__ == '__main__':
    """
    Use for CLI purposes
    """

    parser = argparse.ArgumentParser(description="Stores Secure strings in SSM")
    parser.add_argument('--key-id', '-k', required=True)
    parser.add_argument('--stack-name', '-s', required=True)

    args = parser.parse_args()

    lambda_handler(
        {
            "StackId": "arn:aws:cloudformation:us-west-2:EXAMPLE/stack-name/guid",
            "ResponseURL": "http://pre-signed-S3-url-for-response",
            "ResourceProperties":         {
                'StackName': args.stack_name,
                'KeyId': args.key_id
            },
            "RequestType": "Create",
            "ResourceType": "Custom::TestResource",
            "RequestId": "unique id for this create request",
            "LogicalResourceId": "MyTestResource"
        },
        {}
    )
