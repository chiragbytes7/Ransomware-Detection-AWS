import boto3
import json
from datetime import datetime, timedelta,timezone
from script import verdict 

# AWS configuration
AWS_REGION = 'us-east-1'
SENSITIVE_OBJECT = 'credit-card-data.csv'
LOOKBACK_HOURS = 5  # Adjust this based on your needs
DATABASE = 'irworkshopgluedatabase'
TABLE = 'irworkshopgluetablecloudtrail'
ATHENA_OUTPUT_BUCKET = 'resultstdir'

# Global variable

# Time range for querying
end_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
start_time = datetime.now(timezone.utc - timedelta(hours=LOOKBACK_HOURS)).strftime('%Y-%m-%d %H:%M:%S')

# Create Athena client
athena_client = boto3.client('athena', region_name=AWS_REGION)

# First query to fetch S3 data events related to the sensitive object
query1 = f"""
SELECT * 
FROM "{DATABASE}"."{TABLE}" 
WHERE requestParameters LIKE '%{SENSITIVE_OBJECT}%' 
AND eventName <> 'LookupEvents'
"""

# Execute the first query
response = athena_client.start_query_execution(
    QueryString=query1,
    QueryExecutionContext={'Database': DATABASE},
    ResultConfiguration={'OutputLocation': 's3://{ATHENA_OUTPUT_BUCKET}'}
)

query_execution_id1 = response['QueryExecutionId']

# Wait for the first query to complete
while True:
    query_status = athena_client.get_query_execution(QueryExecutionId=query_execution_id1)
    status = query_status['QueryExecution']['Status']['State']
    
    if status in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
        break

# Fetch results of the first query if succeeded
if status == 'SUCCEEDED':
    result_response = athena_client.get_query_results(QueryExecutionId=query_execution_id1)
    rows = result_response['ResultSet']['Rows']
    
    print(f"Found {len(rows) - 1} events related to '{SENSITIVE_OBJECT}':\n")
    
    # Extract and format the output
    headers = [col['VarCharValue'] for col in rows[0]['Data']]  # Get the header names
    for row in rows[1:]:  # Skip header row
        formatted_data = {}
        for i, cell in enumerate(row['Data']):
            # Check if the cell has 'VarCharValue'
            if 'VarCharValue' in cell:
                formatted_data[headers[i]] = cell['VarCharValue']
            else:
                formatted_data[headers[i]] = None  # Handle missing data
        
        # Check condition and update verdict if necessary
        if formatted_data.get('actor') == 'tdir-workshop-jstiles-dev':
            verdict[1] = True  # Update second index of verdict
            
        # Print formatted data as JSON with indents for readability
        print(json.dumps(formatted_data, indent=4))

    # Proceed to the second query
    query2 = f"""
    SELECT eventtime,eventname,requestparameters 
    FROM "{DATABASE}"."{TABLE}" 
    WHERE userIdentity.username = 'tdir-workshop-jstiles-dev' 
    AND eventName <> 'DeleteObject' 
    AND eventName <> 'GetObject'
    """
    # Execute the second query
    response2 = athena_client.start_query_execution(
        QueryString=query2,
        QueryExecutionContext={'Database': DATABASE},
        ResultConfiguration={'OutputLocation': 's3://{ATHENA_OUTPUT_BUCKET}'}
    )

    query_execution_id2 = response2['QueryExecutionId']

    # Wait for the second query to complete
    while True:
        query_status2 = athena_client.get_query_execution(QueryExecutionId=query_execution_id2)
        status2 = query_status2['QueryExecution']['Status']['State']
        
        if status2 in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
            break

    # Fetch results of the second query if succeeded
    if status2 == 'SUCCEEDED':
        result_response2 = athena_client.get_query_results(QueryExecutionId=query_execution_id2)
        rows2 = result_response2['ResultSet']['Rows']
        
        print(f"\nFound {len(rows2) - 1} events for 'tdir-workshop-jstiles-dev':\n")
        
        # Extract and format the output for the second query
        headers2 = [col['VarCharValue'] for col in rows2[0]['Data']]  # Get the header names
        for row in rows2[1:]:  # Skip header row
            formatted_data2 = {}
            for i, cell in enumerate(row['Data']):
                if 'VarCharValue' in cell:
                    formatted_data2[headers2[i]] = cell['VarCharValue']
                else:
                    formatted_data2[headers2[i]] = None  # Handle missing data
            
            # Check condition and update verdict if necessary
            if formatted_data2.get('actor') == 'tdir-workshop-jstiles-dev':
                verdict[1] = True  # Update second index of verdict
            
            # Print formatted data as JSON with indents for readability
            print(json.dumps(formatted_data2, indent=4))
    else:
        print(f"Second query failed with status: {status2}")
        print("Error:", query_status2['QueryExecution']['Status']['StateChangeReason'])
else:
    print(f"First query failed with status: {status}")
    print("Error:", query_status['QueryExecution']['Status']['StateChangeReason'])

# Print final verdict
print("\nFinal Verdict:", verdict)
