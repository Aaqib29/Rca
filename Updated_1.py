import pandas as pd
import re
from datetime import datetime

# Load the CSV data into a pandas DataFrame
df = pd.read_csv('data.csv')

# Iterate over each row in the DataFrame
for index, row in df.iterrows():
    all_notes = row['Allnotes']
    
    # Extract RCA using regex
    rca_match = re.search(r'RCA:\s*(.*?)\s', all_notes, re.IGNORECASE)
    if rca_match:
        rca = rca_match.group(1).strip()
        df.at[index, 'RCA'] = rca
    
    # Extract Mitigation using regex
    mitigation_match = re.search(r'Mitigations:\s*(.*?)\s', all_notes, re.IGNORECASE)
    if mitigation_match:
        mitigation = mitigation_match.group(1).strip()
        df.at[index, 'Mitigation'] = mitigation
    
    # Extract Time after ACK using regex
    ack_time_match = re.search(r'Ack.\s(.*?)\s\|', all_notes)
    if ack_time_match:
        ack_time_str = ack_time_match.group(1).strip()
        ack_time = datetime.strptime(ack_time_str, '%b %d, %Y, %I:%M:%S %p')
        df.at[index, 'Time after ACK'] = (ack_time - datetime.strptime(row['ACK'], '%b %d, %Y, %I:%M:%S %p')).total_seconds() / 3600  # Assuming 'ACK' is a datetime column in the same format

# Save the updated DataFrame back to a new CSV file
df.to_csv('updated_data.csv', index=False)
