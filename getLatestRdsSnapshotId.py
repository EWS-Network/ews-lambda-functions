#!/usr/bin/env python

import boto3
import time
from datetime import datetime as dt
from datetime import timedelta
import pytz
from pytz import timezone

utc = pytz.utc
client = boto3.client('rds')

def find_the_db_by_cf_stack(stack=""):

    dbs = client.describe_db_instances()['DBInstances']
    for db in dbs:
        tags = client.list_tags_for_resource(ResourceName=db['DBInstanceArn'])['TagList']
        for tag in tags:
            if tag['Key'] == 'aws:cloudformation:stack-name':
                break
        if (tag['Value'].find(stack) >= 0):
            print db['DBInstanceIdentifier']
            return db['DBInstanceIdentifier']


def find_latest_snapshot(DBInstanceId):
    """
    """
    thesnap = None

    now = dt.now(utc)
    snapshots = client.describe_db_snapshots(DBInstanceIdentifier=DBInstanceId)['DBSnapshots']
    difference = snapshots[0]['SnapshotCreateTime']- now
    for snapshot in snapshots:
        if snapshot['SnapshotCreateTime'] - now < difference:
            thesnap = snapshot
    return snapshot['DBSnapshotArn']


if __name__ == '__main__':
    theid = find_the_db_by_cf_stack('corelms')
    print find_latest_snapshot(theid)
