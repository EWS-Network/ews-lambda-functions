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

session = boto3.Session(profile_name='shortl')
client = session.client('acm')

def get_all_certs(certs_list=[],
                  next_token=None):
    """
    """
    if next_token is None:
        certs_r = client.list_certificates(
            CertificateStatuses=['ISSUED'],
            MaxItems=1
        )
    else:
        certs_r = client.list_certificates(
            CertificateStatuses=['ISSUED'],
            NextToken=next_token
        )
    for cert in certs_r['CertificateSummaryList']:
        certs_list.append(cert['CertificateArn'])

    if 'NextToken' in certs_r.keys() and len(certs_r['NextToken']) > 1:
        return get_all_certs(certs_list, certs_r['NextToken'])
    return certs_list


def check_wildcard(fqdn, certificate):
    """
    """

    wildcard_capable = False
    domain_split = fqdn.split('.')

    if len(domain_split) <=3:
        wildcard_capable = True

    if wildcard_capable:
        domain = '*.%s.%s' % (domain_split[len(domain_split) -2], domain_split[len(domain_split) -1])
        print domain
        print certificate['DomainName']
        if domain == certificate['DomainName']:
            return True
        else:
            return False
    else:
        return False


def find_certificate(fqdn, certs_list):
    """
    """
    for cert in certs_list:
        certificate = client.describe_certificate(
            CertificateArn=cert
        )['Certificate']
        if check_wildcard(fqdn, certificate):
            return certificate['CertificateArn']
        if certificate['DomainName'] == fqdn:
            return certificate['CertificateArn']
        else:
            print "Checking all alt names"
            for name in certificate['SubjectAlternativeNames']:
                print name, fqdn
                if name == fqdn:
                    return certificate['CertificateArn']
    return None


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


    for key in ['FQDN']:
        if not key in event['ResourceProperties'].keys():
            return send_response(
                event,
                response,
                status='FAILED',
                reason='FQDN must be present'
            )
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


# FOR CLI TESTING


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description="Script to autogenerate username and password"
        " for a stack_name and store in DynDB"
    )
    parser.add_argument('--domain-name', '-fqdn', help="FQDN covered by the certificate", required=True)

    args = parser.parse_args()
    cert_list = get_all_certs()
    the_cert = find_certificate(args.domain_name, cert_list)
    print cert_list
    print the_cert
