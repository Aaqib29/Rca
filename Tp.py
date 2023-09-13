import pandas as pd
import requests

# Define your VirusTotal API key here
api_key = 'YOUR_VIRUSTOTAL_API_KEY'

# Function to get VirusTotal score and link based on indicator type
def get_vt_score_and_link(indicator, indicator_type):
    endpoint = {
        'url': 'https://www.virustotal.com/vtapi/v2/url/report',
        'ip': 'https://www.virustotal.com/vtapi/v2/ip-address/report',
        'file_hash': 'https://www.virustotal.com/vtapi/v2/file/report'
    }
    url = endpoint.get(indicator_type, None)
    if not url:
        return None, None, None
    
    params = {'apikey': api_key, 'resource': indicator}
    response = requests.get(url, params=params)
    json_response = response.json()
    
    if json_response['response_code'] == 1:
        return json_response['positives'], json_response['total'], json_response['permalink']
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
        indicator_type = row['indicator type']  # Add a column indicating the type of indicator
        
        if indicator:
            vt_positives, vt_total, vt_permalink = get_vt_score_and_link(indicator, indicator_type)
            if vt_positives is not None:
                df.at[index, 'VT Score'] = vt_positives
                df.at[index, 'VT Link'] = vt_permalink
    
    # Save the updated DataFrame back to the Excel file
    with pd.ExcelWriter(file_path, mode='a', engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name=sheet_name, index=False)
