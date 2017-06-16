#!/usr/bin/env python

import uuid
import httplib
import urlparse
import boto3


def get_key(key_alias, next_token=None):
    """
    Main function to get the Key ID
    """

    client = boto3.client('kms')
    if not isinstance(next_token, str):
        aliases_r = client.list_aliases()
    else:
        aliases_r = client.list_aliases(Marker=next_token)

    for alias in aliases_r['Aliases']:
        if alias['AliasName'].endswith(key_alias):
            return {'found': True, 'keyid': alias['TargetKeyId']}
    if aliases_r['Truncated']:
        return get_key(key_alias, aliases_r['NextMarker'])

    return {'found': False, 'Reason': 'The KeyID could not be found with that alias'}


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

    if not check_event_keys(event, ['KeyAlias']):
        return send_response(
            event,
            response,
            status='FAILED',
            reason='Function parameters missing'
        )

    if (event['RequestType'] == 'Update') or \
       (event['RequestType'] == 'Delete'):
        return send_response(event, response)

    keyid = get_key(
        event['ResourceProperties']['KeyAlias']
    )
    if not keyid['found']:
        response['Status'] = 'FAILED'
        response['Reason'] = creds['Reason']
    else:
        response['Data'] = { 'KeyId' : keyid['keyid']}
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


if __name__ == '__main__':
    """
    Main for CLI usage
    """
    import argparse

    parser = argparse.ArgumentParser(
        description="Get the KEY ID from Key Alias"
    )

    parser.add_argument("--key-alias", "-k", help="Friendly name of the KMS Key", required=True)

    args = parser.parse_args()
    key_id = get_key(args.key_alias)
    if key_id['found']:
        print key_id['keyid']
    else:
        print key_id['Reason']
