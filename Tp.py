import pandas as pd
import requests

# Define your VirusTotal API key here
api_key = 'YOUR_VIRUSTOTAL_API_KEY'

# Function to get VirusTotal score and link
def get_vt_score_and_link(indicator):
    endpoint = 'https://www.virustotal.com/api/v3/urls/' + indicator
    headers = {'x-apikey': api_key}
    response = requests.get(endpoint, headers=headers)
    json_response = response.json()

    if response.status_code == 200 and 'data' in json_response:
        data = json_response['data']
        return data['attributes']['last_analysis_stats']['malicious'], data['attributes']['last_analysis_stats']['harmless'], data['links']['self']
    else:
        return None, None, None

# Load your CSV file into a DataFrame
df = pd.read_csv('your_input.csv')  # Replace 'your_input.csv' with your CSV file path

# Create 'VT Score' and 'VT Link' columns initially with empty values
df['VT Score'] = ""
df['VT Link'] = ""

# Iterate through rows in the DataFrame
for index, row in df.iterrows():
    indicator = row['Indicator Value']
    
    if indicator:
        vt_malicious, vt_harmless, vt_permalink = get_vt_score_and_link(indicator)
        if vt_malicious is not None:
            df.at[index, 'VT Score'] = f'Malicious: {vt_malicious}, Harmless: {vt_harmless}'
            df.at[index, 'VT Link'] = vt_permalink

# Save the updated DataFrame to a new CSV file
df.to_csv('output.csv', index=False)  # Replace 'output.csv' with your desired output file name
