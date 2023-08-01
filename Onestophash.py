import re
import pandas as pd
import fitz  # PyMuPDF
import requests

def extract_hashes_from_pdf(pdf_file):
    try:
        # Open the PDF file
        pdf_document = fitz.open(pdf_file)

        # Regular expression pattern for common hash types (e.g., MD5, SHA-256)
        hash_pattern = r'\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b'

        hashes = []
        # Loop through each page and find hashes using regex
        for page_num in range(pdf_document.page_count):
            page = pdf_document.load_page(page_num)
            page_text = page.get_text()
            found_hashes = re.findall(hash_pattern, page_text)
            hashes.extend(found_hashes)

        # Close the PDF document
        pdf_document.close()

        return hashes
    except Exception as e:
        print(f"Error extracting hashes from the PDF: {e}")
        return []

def get_sha256_from_virustotal(api_key, hash_value):
    try:
        url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            return data['data']['attributes']['sha256']
        else:
            return 'NA'
    except Exception as e:
        print(f"Error retrieving SHA256 from VirusTotal: {e}")
        return 'NA'

def add_sha256_from_virustotal(hashes, api_key):
    results = []
    for hash_value in hashes:
        sha256 = get_sha256_from_virustotal(api_key, hash_value)
        results.append({'Hash': hash_value, 'sha256_virustotal': sha256})
    return results

def save_results_to_csv(results, output_file):
    try:
        df = pd.DataFrame(results)
        df.to_csv(output_file, index=False)
        print(f"Results saved to {output_file}")
    except Exception as e:
        print(f"Error saving results to CSV: {e}")

if __name__ == "__main__":
    # Replace 'input_file.pdf' with the path to your PDF file
    pdf_file_path = 'input_file.pdf'
    extracted_hashes = extract_hashes_from_pdf(pdf_file_path)

    # Replace 'YOUR_VIRUSTOTAL_API_KEY' with your actual VirusTotal API key
    virustotal_api_key = "YOUR_VIRUSTOTAL_API_KEY"

    if extracted_hashes:
        # Search hashes on VirusTotal and get the SHA256 results
        results = add_sha256_from_virustotal(extracted_hashes, virustotal_api_key)

        # Replace 'output_file.csv' with the desired name for the output CSV file
        output_csv = "output_file.csv"

        # Save the results to a CSV file
        save_results_to_csv(results, output_csv)
    else:
        print("No hashes were extracted from the PDF.")
