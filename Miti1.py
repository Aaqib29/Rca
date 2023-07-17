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

# Function to extract mitigation information
def extract_mitigation(row, rca_data):
    rca_index = row.find(rca_data)  # Find the position of RCA data in the row

    if rca_index == -1:
        return None

    # Define the regular expression pattern for extracting mitigation
    regex_pattern = r'(?<={0})(.*?)(?=\.)'.format(re.escape(rca_data))
    match = re.search(regex_pattern, row, re.IGNORECASE | re.DOTALL)

    if match:
        mitigation = match.group(0).strip()
        return mitigation
    else:
        return None

# Apply the function to the DataFrame to create a new column 'rca_data'
df['rca_data'] = df['allNotes'].apply(extract_rca_data)

# Apply the function to extract stratification information and create a new column 'Stratification'
df['Stratification'] = df['allNotes'].apply(extract_stratification)

# Apply the function to extract mitigation information and create a new column 'Mitigation'
df['Mitigation'] = df.apply(lambda row: extract_mitigation(row['allNotes'], row['rca_data']), axis=1)

# Save the updated DataFrame back to a new CSV file
df.to_csv('output_data.csv', index=False)

# Print the resulting DataFrame
print(df)
