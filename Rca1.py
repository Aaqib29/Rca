import pandas as pd
import re

# Load the CSV data into a pandas DataFrame
df = pd.read_csv('data.csv')

# Create a new column for RCA
df['RCA'] = ""

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
    
        # Find the index where the Stratification ends
        stratification_end_idx = all_notes.find(stratification) + len(stratification)
        
        # Find the index where Mitigations starts after the Stratification
        mitigations_start_idx = all_notes.find('Mitigations:', stratification_end_idx)
        
        # Extract the RCA section between Stratification and Mitigations
        rca = all_notes[stratification_end_idx:mitigations_start_idx].strip()
        df.at[index, 'RCA'] = rca

# Save the updated DataFrame back to a new CSV file
df.to_csv('rca_data.csv', index=False)
