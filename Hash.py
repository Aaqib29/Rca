import pandas as pd
import requests

def get_sha256_from_virustotal(api_key, hash_value):
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        return data['data']['attributes']['sha256']
    else:
        return 'NA'

def add_sha256_from_virustotal(input_file, output_file, api_key):
    # Read the CSV file into a pandas DataFrame
    df = pd.read_csv(input_file)

    # Create a new column to store the SHA256 hashes from VirusTotal
    df['sha256_virustotal'] = df['Hash'].apply(lambda x: get_sha256_from_virustotal(api_key, x))

    # Save the DataFrame with the new column to a new CSV file
    df.to_csv(output_file, index=False)

if __name__ == "__main__":
    # Replace 'input_file.csv' with the path to your input CSV file
    input_csv = "input_file.csv"

    # Replace 'output_file.csv' with the desired name for the output CSV file
    output_csv = "output_file.csv"

    # Replace 'YOUR_VIRUSTOTAL_API_KEY' with your actual VirusTotal API key
    virustotal_api_key = "YOUR_VIRUSTOTAL_API_KEY"

    add_sha256_from_virustotal(input_csv, output_csv, virustotal_api_key)
