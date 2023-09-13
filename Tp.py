import pandas as pd
import requests

# Define your VirusTotal API key here
api_key = 'YOUR_VIRUSTOTAL_API_KEY'

# Function to get VirusTotal score and link for URLs
def get_vt_score_and_link(url):
    endpoint = 'https://www.virustotal.com/api/v3/urls/' + url
    headers = {'x-apikey': api_key}
    response = requests.get(endpoint, headers=headers)
    json_response = response.json()
    
    if 'data' in json_response:
        data = json_response['data']
        return data['attributes']['last_analysis_stats']['malicious'], data['attributes']['last_analysis_stats']['harmless'], data['links']['self']
    else:
        return None, None, None

# Load your XLSX file with multiple sheets
file_path = 'your_xlsx_file.xlsx'
xls = pd.ExcelFile(file_path)

# Iterate through each sheet
for sheet_name in xls.sheet_names:
    df = xls.parse(sheet_name)
    
    # Create 'VT Score' and 'VT Link' columns initially with empty values
    df['VT Score'] = ""
    df['VT Link'] = ""

    # Iterate through rows in the DataFrame
    for index, row in df.iterrows():
        indicator = row['indicator value']
        
        if indicator:
            vt_malicious, vt_harmless, vt_permalink = get_vt_score_and_link(indicator)
            if vt_malicious is not None:
                df.at[index, 'VT Score'] = f'Malicious: {vt_malicious}, Harmless: {vt_harmless}'
                df.at[index, 'VT Link'] = vt_permalink
    
    # Save the updated DataFrame back to the Excel file
    with pd.ExcelWriter(file_path, mode='a', engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name=sheet_name, index=False)
