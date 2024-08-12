# Script name: ransomware_detection.py

import boto3
import json
from datetime import datetime, timedelta

# Global variable to modify the verdict array in main script
verdict = [0]

# AWS configuration constants
AWS_REGION = 'us-east-1'
SUSPICIOUS_BUCKET_PREFIX = 'we-stole-ur-data-'
SUSPICIOUS_OBJECT = 'all_your_data_are_belong_to_us.txt'
LOOKBACK_HOURS = 5

def detect_ransomware_activity():
    global verdict
    
    # Initialize boto3 clients
    s3_client = boto3.client('s3', region_name=AWS_REGION)
    cloudtrail_client = boto3.client('cloudtrail', region_name=AWS_REGION)

    # Time range for fetching CloudTrail events
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=LOOKBACK_HOURS)

    # Fetch CloudTrail events for CreateBucket actions
    response = cloudtrail_client.lookup_events(
        LookupAttributes=[
            {
                'AttributeKey': 'EventName',
                'AttributeValue': 'CreateBucket'
            }
        ],
        StartTime=start_time,
        EndTime=end_time
    )

    events = response['Events']
    while 'NextToken' in response:
        response = cloudtrail_client.lookup_events(
            LookupAttributes=[
                {
                    'AttributeKey': 'EventName',
                    'AttributeValue': 'CreateBucket'
                }
            ],
            StartTime=start_time,
            EndTime=end_time,
            NextToken=response['NextToken']
        )
        events.extend(response['Events'])

    # Find the IAM user who created the suspicious bucket
    suspicious_buckets = []
    for event in events:
        event_data = json.loads(event['CloudTrailEvent'])
        bucket_name = event_data.get('requestParameters', {}).get('bucketName', '')
        if bucket_name.startswith(SUSPICIOUS_BUCKET_PREFIX):
            suspicious_buckets.append(event_data)

    if not suspicious_buckets:
        print('No suspicious buckets found.')
        # Set the verdict array - 0th index to 0 (no suspicious bucket found)
        verdict[0] = 0
    else:
        for bucket in suspicious_buckets:
            iam_user = bucket['userIdentity']['userName']
            event_time = bucket['eventTime']

            print(f'IAM User who created the bucket: {iam_user}')
            print(f'Bucket creation time: {event_time}')

            # Fetch CloudTrail events for actions performed by the IAM user who created the bucket
            response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'Username',
                        'AttributeValue': iam_user
                    }
                ],
                StartTime=start_time,
                EndTime=end_time
            )

            user_events = response['Events']
            while 'NextToken' in response:
                response = cloudtrail_client.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'Username',
                            'AttributeValue': iam_user
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    NextToken=response['NextToken']
                )
                user_events.extend(response['Events'])

            user_events_sorted = sorted(user_events, key=lambda x: x['EventTime'])

            for event in user_events_sorted:
                event_data = json.loads(event['CloudTrailEvent'])
                print(f"Event time: {event_data['eventTime']}, Event name: {event_data['eventName']}")

            # Check if the suspicious object was uploaded by the same IAM user
            response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'PutObject'
                    }
                ],
                StartTime=start_time,
                EndTime=end_time
            )

            put_object_events = response['Events']
            while 'NextToken' in response:
                response = cloudtrail_client.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'EventName',
                            'AttributeValue': 'PutObject'
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    NextToken=response['NextToken']
                )
                put_object_events.extend(response['Events'])

            for event in put_object_events:
                event_data = json.loads(event['CloudTrailEvent'])
                if SUSPICIOUS_OBJECT in event_data.get('requestParameters', {}).get('key', ''):
                    upload_user = event_data['userIdentity']['userName']
                    print(f'IAM User who uploaded the ransom note: {upload_user}')
                    if upload_user == iam_user:
                        print('The IAM user who created the bucket is the same as the one who uploaded the ransom note.')
                    else:
                        print('The IAM user who created the bucket is different from the one who uploaded the ransom note.')
                    break
            else:
                print('No ransom note upload events found.')
            
            # Set the verdict array - 0th index to 1 (suspicious bucket found)
            verdict[0] = 1

# Entry point when script is run directly
if __name__ == "__main__":
    detect_ransomware_activity()
