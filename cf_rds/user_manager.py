#!/usr/bin/env python

import base64
import json
import random
import string
import hashlib
import uuid
import httplib
import urlparse
import boto3
import pymysql as db



class DBManager(object):
    """
    """

    def __init__(self, root_user, root_password, endpoint='localhost', port=3306):
        """
        """

        self.endpoint = endpoint
        self.root_user = root_user

        self.connection = db.connect(user=root_user, passwd=root_password, host=endpoint)
        self.cursor = self.connection.cursor()


    def __repr__(self):
        return "%s - %s" % (self.root_user, self.endpoint)


    def create_user_grant(self, db_name, username, password):
        """
        """
        query = "grant all privileges on %s.* to '%s'@'%%' identified by '%s'" % (
            db_name,
            username,
            password
        )
        try:
            self.cursor.execute(query)
            return True
        except Exception as e:
            print 'Failed to grant privileges. Reason :', e
            return False

    def create_db(self, db_name):
        """
        """
        try:
            self.cursor.execute('CREATE DATABASE %s' % (db_name))
            return True
        except Exception as e:
            print 'Error creating the DB. Reason :', e
            return False


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

    # There is nothing to do for a delete or update request

    if (event['RequestType'] == 'Delete') or \
       (event['RequestType'] == 'Update'):
        return send_response(event, response)


    for key in ['MasterUser', 'MasterPassword', 'RdsEndpoint',
                'UserName', 'UserPassword', 'DatabaseName']:
        if not key in event['ResourceProperties'].keys():
            return send_response(
                event,
                response,
                status='FAILED',
                reason='Missing parameters'
            )

    db_name = event['ResourceProperties']['DatabaseName']
    root_user = event['ResourceProperties']['MasterUser']
    root_password = event['ResourceProperties']['MasterPassword']
    user_name = event['ResourceProperties']['UserName']
    user_password = event['ResourceProperties']['UserPassword']
    endpoint = event['ResourceProperties']['RdsEndpoint']

    manager = DBManager(
        root_user,
        root_password,
        endpoint=endpoint
    )

    if manager.create_db(db_name):
        if manager.create_user_grant(db_name, user_name, user_password):
            print "User successfully granted all privileges"
        else:
            response['Status'] = 'FAILED'
            response['Reason'] = 'Failed to assign privileges to user'
            print "Failed to assign privileges to user"
    else:
        response['Status'] = 'FAILED'
        response['Reason'] = 'Database was not created - Failure'


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


if __name__ == '__main__':

    manager = DBManager('root', 'Hermine', db_name='db_test')
    print manager
    if manager.create_db('db_test4'):
        if manager.create_user_grant('db_test4', 'toto', 'Titiata'):
            print "User successfully granted all privileges"
        else:
            print "Failed to assign privileges to user"

    else:
        print "Database was not created"
