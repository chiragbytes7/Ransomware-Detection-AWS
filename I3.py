import boto3
import json
from script import verdict

# AWS configuration
AWS_REGION = 'us-east-1'
DATABASE = 'irworkshopgluedatabase'
TABLE = 'irworkshopgluetablecloudtrail'

# Create Athena client
athena_client = boto3.client('athena', region_name=AWS_REGION)

# Function to execute Athena queries
def execute_athena_query(query):
    response = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={'Database': DATABASE},
        ResultConfiguration={'OutputLocation': 's3://restdir'}
    )
    query_execution_id = response['QueryExecutionId']
    
    # Wait for query to complete
    while True:
        query_status = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
        status = query_status['QueryExecution']['Status']['State']
        
        if status in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
            break
    
    return status, query_execution_id, query_status

# Function to get query results
def get_query_results(query_execution_id):
    result_response = athena_client.get_query_results(QueryExecutionId=query_execution_id)
    rows = result_response['ResultSet']['Rows']
    return rows

# Query to fetch bucket deletion events
delete_bucket_query = f"""
SELECT eventTime 
FROM "{DATABASE}"."{TABLE}" 
WHERE eventName = 'DeleteBucket'
"""

# Execute the DeleteBucket query
status, delete_bucket_query_execution_id, delete_bucket_query_status = execute_athena_query(delete_bucket_query)

# Fetch results for DeleteBucket if succeeded
if status == 'SUCCEEDED':
    delete_bucket_rows = get_query_results(delete_bucket_query_execution_id)
    num_delete_buckets = len(delete_bucket_rows) - 1  # Exclude header row
    print(f"Found {num_delete_buckets} bucket deletion events.")
    
    # Update verdict if bucket deletion events are found
    if num_delete_buckets > 0:
        # Update verdict array for bucket deletion events
        verdict[2] = 1
else:
    print(f"DeleteBucket query failed with status: {status}")
    print("Error:", delete_bucket_query_status['QueryExecution']['Status']['StateChangeReason'])

# Query to fetch GetObject events
get_object_query = f"""
SELECT eventTime 
FROM "{DATABASE}"."{TABLE}" 
WHERE eventName = 'GetObject'
"""

# Execute the GetObject query
status, get_object_query_execution_id, get_object_query_status = execute_athena_query(get_object_query)

# Fetch results for GetObject if succeeded
if status == 'SUCCEEDED':
    get_object_rows = get_query_results(get_object_query_execution_id)
    num_get_objects = len(get_object_rows) - 1  # Exclude header row
    print(f"Found {num_get_objects} GetObject events.")

    # Update verdict based on conditions
    if num_get_objects > 100:
        verdict[2] = 1  # Assuming `verdict` is defined and accessible globally
        print("Verdict updated: High risk detected (GetObject events > 100)")
    else:
        print("GetObject events <= 100, no high risk detected.")
else:
    print(f"GetObject query failed with status: {status}")
    print("Error:", get_object_query_status['QueryExecution']['Status']['StateChangeReason'])
