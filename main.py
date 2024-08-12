import subprocess
verdict = [0,0,0,0]
# Define paths to your scripts
script_paths = [
    'i1.py',
    'i2.py',
    'i3.py',
    'i4.py'
]

# Iterate through script paths and run each script
for script_path in script_paths:
    result = subprocess.run(['python3', script_path], capture_output=True, text=True)
    
    # Print output of each script
    print(f"Output of {script_path}:")
    print(result.stdout)
    
    # Check for errors, if any
    if result.returncode != 0:
        print(f"Error running {script_path}:")
        print(result.stderr)

sum = 0
for i in verdict:
    if i == 1:
        sum = sum + 1

if sum == 0:
    print('very low severity')
if sum == 1:
    print('low severity')
if sum == 2:
    print('moderate severity')
if sum == 3:
    print('high severity')
if sum == 4:
    print('very high severity')