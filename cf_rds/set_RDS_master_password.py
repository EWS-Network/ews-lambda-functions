#!/usr/bin/env python

"""

Lambda function to fetch from DynamoDb the Master user and password of an RDS Instance

"""
import base64
import boto3
import json
import random
import string
import hashlib
from boto3.dynamodb.conditions import Key, Attr



def put_password_in_dynamodb(table_name,
                             stack_name,
                             user_name,
                             b64_encrypted_password,
                             attribute_name,
                             update=False):
    """
    Function to store the b64 password in DynamoDB
    :param table_name: Name of the table
    :param stack_name:
    :param password: string of the base64 encrypted password
    """

    hash_string = hashlib.sha256(stack_name).hexdigest().strip()
    client = boto3.resource('dynamodb')
    table = client.Table(table_name)

    print attribute_name

    response = table.query(
        KeyConditionExpression=Key(attribute_name).eq(hash_string)
    )
    if response['Count'] != 0 and not update:
        print "Already exists and not updating - Skipping"
        return False

    elif (response['Count'] != 0 and update) or \
         (response['Count'] == 0):

        response = table.put_item(
            Item={
                attribute_name : hash_string,
                'user_name' : user_name,
                'b64_password': b64_encrypted_password
            }
        )

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
    stack_name = 'tst-stack'
    username = generate_random_string(10, True)
    password = generate_random_string(21)

    put_password_in_dynamodb('rds_dev', stack_name, username, password, 'rds_id')
