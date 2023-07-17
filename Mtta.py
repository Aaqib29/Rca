import pandas as pd
import re

# Load the CSV file into a DataFrame
df = pd.read_csv('data.csv')

# Specify the columns you want to keep
specified_columns = ['id', 'magnitude', 'formattedClosedDate', 'localizedCloseReason',
                     'description', 'severity', 'formattedStartTime', 'allNotes']

# Drop columns that are not in the specified_columns list
columns_to_drop = [col for col in df.columns if col not in specified_columns]
df.drop(columns=columns_to_drop, inplace=True)

# Function to extract data based on RCA and Mitigation keywords
def extract_rca_data(row):
    regex_pattern = r'RCA:(.*?)(?=Mitigations?|$)'  # Regular expression to extract data between RCA and Mitigation(s)
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
    # Use a more specific pattern to stop at the specified keywords or none
    mitigation_match = re.search(r'Mitigations?:(.*?)(?:Seniorsocuser|Soc user|Admin|\| Ack|$)', row, re.IGNORECASE | re.DOTALL)
    if mitigation_match:
        mitigation = mitigation_match.group(1).strip()
        return mitigation
    else:
        return "None"

# Function to extract time mentioned after "ack" or "Ack"
def extract_time_after_ack(row):
    time_match = re.search(r'\b(?i)ack(.*?)(?=\s(?:AM|PM))\s(?:AM|PM)', row)
    if time_match:
        time = time_match.group(0).strip()  # Get the entire match including AM or PM
        return time
    else:
        return None

# Function to calculate the time difference between formattedStartTime and Time after ACK
def calculate_time_difference(row):
    formatted_start_time = row['formattedStartTime']
    time_after_ack = row['Time after ACK']
    
    if formatted_start_time and time_after_ack:
        formatted_start_time = pd.to_datetime(formatted_start_time, format='%b %d, %Y, %I:%M:%S %p')
        time_after_ack = pd.to_datetime(time_after_ack, format='%b %d, %Y, %I:%M:%S %p')
        time_difference = time_after_ack - formatted_start_time
        return time_difference.total_seconds() / 60  # Return time difference in minutes
    else:
        return None

# Apply the function to the DataFrame to create new columns
df['rca_data'] = df['allNotes'].apply(extract_rca_data)
df['Stratification'] = df['allNotes'].apply(extract_stratification)
df['Mitigation'] = df['allNotes'].apply(extract_mitigation)
df['Time after ACK'] = df['allNotes'].apply(extract_time_after_ack)

# Calculate the MTTA (Mean Time to Acknowledge) and create a new column for it
df['MTTA'] = df.apply(calculate_time_difference, axis=1)

# Save the updated DataFrame back to a new CSV file
df.to_csv('output_data.csv', index=False)

# Print the resulting DataFrame
print(df)