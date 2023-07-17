import pandas as pd
import re
from datetime import datetime

# Load the CSV data into a pandas DataFrame
df = pd.read_csv('data.csv')

# Create new columns for Stratification, RCA, Mitigation, and Time after ACK
df['Stratification'] = ""
df['RCA'] = ""
df['Mitigation'] = ""
df['Time after ACK'] = ""

# Iterate over each row in the DataFrame
for index, row in df.iterrows():
    all_notes = row['Allnotes']
    
    # Check if "Reported to SIEM" is present in the notes and skip processing
    if "Reported to SIEM" in all_notes:
        continue
    
    # Extract Stratification using regex
    stratification_match = re.search(r'This offense was closed with reason: (.*?)\.', all_notes, re.IGNORECASE)
    if stratification_match:
        stratification = stratification_match.group(1).strip()
        df.at[index, 'Stratification'] = stratification
    
    # Extract all RCA sections using regex
    rca_matches = re.findall(r'RCA:(.*?)(?=\s*Mitigations:|$)', all_notes, re.IGNORECASE | re.DOTALL)
    if rca_matches:
        # Take the first RCA mentioned after Stratification
        rca = next((rca.strip() for rca in rca_matches if stratification in rca), '').strip()
        df.at[index, 'RCA'] = rca
    
    # Extract Mitigation using regex
    mitigation_match = re.search(r'Mitigations:(.*?)[.!?]', all_notes, re.IGNORECASE | re.DOTALL)
    if mitigation_match:
        mitigation = mitigation_match.group(1).strip()
        df.at[index, 'Mitigation'] = mitigation.strip()
    
    # Extract Time after ACK using regex
    ack_time_match = re.search(r'Ack(.*?)(?:\"|$)', all_notes, re.IGNORECASE | re.DOTALL)
    if ack_time_match:
        ack_time_str = ack_time_match.group(1).strip()
        try:
            ack_time = datetime.strptime(ack_time_str, '%b %d, %Y, %I:%M:%S %p')
            df.at[index, 'Time after ACK'] = ack_time.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            # Try parsing with different format if the first one fails
            try:
                ack_time = datetime.strptime(ack_time_str, '%b %d, %Y, %I:%M:%S %p')
                df.at[index, 'Time after ACK'] = ack_time.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                print(f"Error parsing time for row {index}: {ack_time_str}")

# Save the updated DataFrame back to a new CSV file
df.to_csv('updated_data.csv', index=False)
