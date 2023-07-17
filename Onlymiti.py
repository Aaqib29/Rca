import pandas as pd
import re

# Load the CSV file into a DataFrame
df = pd.read_csv('data.csv')

# Function to extract data based on RCA and Mitigation keywords
def extract_rca_data(row):
    regex_pattern = r'RCA:(.*?)(?=Mitigation|$)'  # Regular expression to extract data between RCA and Mitigation
    match = re.search(regex_pattern, row)
    if match:
        return match.group(1).strip()
    else:
        return None

# Function to extract stratification information
def extract_stratification(row):
    stratification_match = re.search(r'This offense was closed with reason: (.*?)\.', row, re.IGNORECASE)
    if stratification_match:
        stratification = stratification_match.group(1).strip()
        return stratification
    else:
        return None

# Function to extract mitigation information
def extract_mitigation(row):
    mitigation_match = re.search(r'Mitigation:(.*?)(?:\.$|[^.\d])', row, re.IGNORECASE)
    if mitigation_match:
        mitigation = mitigation_match.group(1).strip()
        return mitigation
    else:
        return None

# Apply the function to the DataFrame to create a new column 'rca_data'
df['rca_data'] = df['allNotes'].apply(extract_rca_data)

# Apply the function to extract stratification information and create a new column 'Stratification'
df['Stratification'] = df['allNotes'].apply(extract_stratification)

# Apply the function to extract mitigation information and create a new column 'Mitigation'
df['Mitigation'] = df['allNotes'].apply(extract_mitigation)

# Save the updated DataFrame back to a new CSV file
df.to_csv('output_data.csv', index=False)

# Print the resulting DataFrame
print(df)
