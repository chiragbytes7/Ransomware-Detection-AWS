import boto3
import time
import json
from datetime import datetime

# Importing verdict from another script (assuming it's defined there)
from script import verdict

# Initialize Athena and GuardDuty clients
athena_client = boto3.client('athena')
guardduty_client = boto3.client('guardduty')

# Replace with your GuardDuty detector ID and Athena details
DETECTOR_ID = '46c862053850277fc4f3291b970b0792'
DATABASE = 'irworkshopgluedatabase'
TABLE = 'irworkshopgluetablecloudtrail'
S3_OUTPUT = 's3://resultstdir'

# Function to execute Athena queries
def execute_athena_query(query):
    response = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={'Database': DATABASE},
        ResultConfiguration={'OutputLocation': S3_OUTPUT}
    )
    query_execution_id = response['QueryExecutionId']
    
    # Wait for query to complete
    while True:
        query_status = athena_client.get_query_execution(QueryExecutionId=query_execution_id)
        state = query_status['QueryExecution']['Status']['State']
        if state in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
            break
        time.sleep(2)
    
    return state, query_execution_id, query_status

# Function to get query results
def get_query_results(query_execution_id):
    result_response = athena_client.get_query_results(QueryExecutionId=query_execution_id)
    rows = result_response['ResultSet']['Rows']
    return rows

# Query Athena for access to 'company-secrets.doc'
query_company_secrets = f"""
SELECT * FROM "{DATABASE}"."{TABLE}" 
WHERE requestparameters LIKE '%company-secrets.doc%'
"""

# Execute Athena query for 'company-secrets.doc'
state, query_id_company_secrets, query_status_company_secrets = execute_athena_query(query_company_secrets)

# Fetch results if query succeeded
if state == 'SUCCEEDED':
    results_company_secrets = get_query_results(query_id_company_secrets)
    
    if len(results_company_secrets) > 1:
        print("Access to 'company-secrets.doc' detected:")
        headers = [col['VarCharValue'] for col in results_company_secrets[0]['Data']]
        for row in results_company_secrets[1:]:
            formatted_data = {}
            for i, cell in enumerate(row['Data']):
                if 'VarCharValue' in cell:
                    formatted_data[headers[i]] = cell['VarCharValue']
                else:
                    formatted_data[headers[i]] = None
            print(json.dumps(formatted_data, indent=4))
    else:
        print("No evidence that 'company-secrets.doc' was accessed or deleted.")
else:
    print(f"Athena query {query_id_company_secrets} did not succeed. State: {state}")

# Query Athena for 'PutBucketLogging' events
query_put_bucket_logging = f"""
SELECT * FROM "{DATABASE}"."{TABLE}" 
WHERE eventname = 'PutBucketLogging'
"""

# Execute Athena query for 'PutBucketLogging' events
state, query_id_put_bucket_logging, query_status_put_bucket_logging = execute_athena_query(query_put_bucket_logging)

# Fetch results if query succeeded
if state == 'SUCCEEDED':
    results_put_bucket_logging = get_query_results(query_id_put_bucket_logging)
    
    if len(results_put_bucket_logging) > 1:
        print("PutBucketLogging events detected:")
        headers = [col['VarCharValue'] for col in results_put_bucket_logging[0]['Data']]
        for row in results_put_bucket_logging[1:]:
            formatted_data = {}
            for i, cell in enumerate(row['Data']):
                if 'VarCharValue' in cell:
                    formatted_data[headers[i]] = cell['VarCharValue']
                else:
                    formatted_data[headers[i]] = None
            print(json.dumps(formatted_data, indent=4))
    else:
        print("No PutBucketLogging events found.")
else:
    print(f"Athena query {query_id_put_bucket_logging} did not succeed. State: {state}")

# Custom JSON encoder for datetime objects
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)

# Fetch and display GuardDuty findings
try:
    response = guardduty_client.list_findings(
        DetectorId=DETECTOR_ID,
        FindingCriteria={
            'Criterion': {
                'type': {
                    'Eq': ['Stealth:S3/ServerAccessLoggingDisabled']
                }
            }
        },
        MaxResults=10  # Adjust as needed
    )
    finding_ids = response.get('FindingIds', [])
    
    if not finding_ids:
        print("No findings found for Stealth:S3/ServerAccessLoggingDisabled")
    else:
        print("GuardDuty findings:")
        verdict[3] = 1  # Update verdict[3] to 1 if there are findings
        for finding_id in finding_ids:
            finding = guardduty_client.get_findings(
                DetectorId=DETECTOR_ID,
                FindingIds=[finding_id]
            )
            if finding and 'Findings' in finding:
                for f in finding['Findings']:
                    readable_finding = {
                        'Title': f.get('Title'),
                        'Description': f.get('Description'),
                        'Severity': f.get('Severity'),
                        'CreatedAt': f.get('CreatedAt'),
                        'Service': f.get('Service')
                    }
                    print(json.dumps(readable_finding, indent=4, cls=DateTimeEncoder))  # Pretty-print the finding as JSON
except Exception as e:
    print(f"Error fetching GuardDuty findings: {e}")


print("\nFinal verdict:", verdict)
