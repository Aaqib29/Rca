import pandas as pd
import requests
import os

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

# Define the path to your XLSX file within Google Colab
file_name = 'your_xlsx_file.xlsx'  # Replace with your XLSX file name
file_path = os.path.join('/content', file_name)

# Load your XLSX file with multiple sheets
xls = pd.ExcelFile(file_path)

# Create a new Excel file for the updated data within Google Colab
output_file_path = os.path.join('/content', file_name)  # Use the same file name

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
    
    # Save the updated DataFrame to the same Excel file without the "updated_" prefix
    with pd.ExcelWriter(output_file_path, mode='a', engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name=sheet_name, index=False)

# Provide a download link for the updated file in Colab
output_file_path
