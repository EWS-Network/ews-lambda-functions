#!/usr/bin/env python

"""

Lambda function to fetch from DynamoDb the Master user and password of an RDS Instance

"""
import base64
import boto3
import json
import hashlib
from boto3.dynamodb.conditions import Key, Attr


def get_password_string(table_name, stack_name):
    """
    :param table_name: Name of the DynDB table that stores
    :param stack_name: Name of the Stack that created the RDS Instance
    """

    stack_hash = hashlib.sha256()
    stack_hash.update(stack_name)
    hash_string = stack_hash.hexdigest().strip()

    print hash_string

    client = boto3.resource('dynamodb')
    table = client.Table(table_name)

    response = table.query(
        KeyConditionExpression=Key('rds_id').eq(hash_string)
    )
    if response['Count'] > 1:
        print "PROBLEM ! There is more than one entry - Failure"
    elif response['Count'] == 0:
        print "PROBLEM ! There is no record  - Failure"
    else:
        data = response['Items'][0]
        print data['b64_password']
        return data


def decrypt_b64_password(b64_password):
    """
    :param b64_password: b64 encoded password encrypted with KMS
    """

    password_encrypted = base64.b64decode(password_b64)
    client = boto3.client('kms')
    password = client.decrypt(CiphertextBlob=password_encrypted)
    return password['Plaintext']


if __name__ == '__main__':
    creds = get_password_string('rds_dev', 'tst-stack')
    password = decrypt_b64_password(creds['b64_password'])
    print password()

