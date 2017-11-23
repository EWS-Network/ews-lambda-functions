#!/usr/bin/env python

"""

Scripting to get the current EC2 On-Demand price of a given instance type

https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/index.json
 -> https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/20171117190039/eu-west-1/index.json

"""

import re
import uuid
import json
import httplib
import urlparse
import argparse
import requests


def get_service_details(service_name="AmazonEC2"):
    """
    :param region_name: Name of the region to use for pricing
    :return: String() of the URL for the AmazonEC2 pricing of the region
    """

    r_services = requests.get("https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/index.json")
    services = r_services.json()['offers']

    if service_name in services.keys():
        return services[service_name]


def build_region_pricing_url(service_details, region_name):
    """
    :param service_deails: dict of the service URLs
    :return: URL of the pricing of the service
    """

    core_url = "https://pricing.us-east-1.amazonaws.com"
    url = core_url + service_details['currentRegionIndexUrl']
    r = requests.get(url)
    regions = r.json()['regions']

    if region_name in regions.keys():
        path = regions[region_name]['currentVersionUrl']
    else:
        return
    return "%s%s" % (core_url, path)


def get_instance_type_sku(instance_type, region_url, os_family="Linux"):
    """
    """

    r = requests.get(region_url)
    products = r.json()['products']

    for product in products:
        if 'attributes' in products[product].keys() and \
           'instanceType' in products[product]['attributes'].keys() and \
           products[product]['attributes']['instanceType'] == instance_type and \
           products[product]['attributes']['operatingSystem'] == os_family and \
           products[product]['attributes']['tenancy'] == "Shared":
            return product


def get_sku_rate(sku, region_url, terms="OnDemand"):
    """
    """

    terms_to_code = {
        "OnDemand" : "JRTCKXETXF"
        }

    r = requests.get(region_url)
    gl_terms = r.json()['terms']

    if not terms in gl_terms.keys() and terms in terms_to_code.keys():
        return None

    sku_code = "%s.%s" % (sku, terms_to_code[terms])
    if not sku in gl_terms[terms]:
        return None

    gl_dim = gl_terms[terms][sku][sku_code]['priceDimensions']
    for dimension in gl_dim:
        return (gl_dim[dimension]['pricePerUnit']['USD'])


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

    if event['RequestType'] == 'Delete':
        return send_response(event, response)

    for key in ['InstanceType', 'Region']:
        if not key in event['ResourceProperties'].keys():
            return send_response(
                event,
                response,
                status='FAILED',
                reason='The properties TableName and StackName must be present'
            )

    service_details = get_service_details()
    region_url = build_region_pricing_url(
        service_details,
        event['ResourceProperties']['Region']
    )
    sku = get_instance_type_sku(
        event['ResourceProperties']['InstanceType'],
        region_url
    )
    cost_per_hour = get_sku_rate(sku, region_url)

    if not cost_per_hour:
        response['Status'] = 'FAILED'
    else:
        response['Data'] = {
            'CostPerHour': cost_per_hour
        }
    response['Reason'] = "%s costs %s in %s" % (
        event['ResourceProperties']['InstanceType'],
        cost_per_hour,
        event['ResourceProperties']['Region']
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

# FOR CLI USAGE

if __name__ == '__main__':


    parser = argparse.ArgumentParser("Get EC2 pricing")

    parser.add_argument("--instance-type", type=str, required=True)
    parser.add_argument("--region", type=str, required=True)

    args = parser.parse_args()
    service_details = get_service_details()

    instance_type = args.instance_type
    region_name = args.region

    region_url = build_region_pricing_url(service_details, region_name)
    sku = get_instance_type_sku(instance_type, region_url)
    cost_per_hour = get_sku_rate(sku, region_url)

    print ("Type %s costs %s in %s" % (instance_type, cost_per_hour, region_name))
