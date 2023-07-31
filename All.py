import re
import pandas as pd
import fitz  # PyMuPDF

def extract_data_from_pdf(pdf_file):
    # Open the PDF file
    pdf_document = fitz.open(pdf_file)

    # Regular expression pattern for common hash types (e.g., MD5, SHA-256)
    hash_pattern = r'\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b'

    # Regular expression pattern for URLs/domains (both with and without https)
    url_pattern = r'https?://(?:www\.)?[\w.-]+(?:\.[a-zA-Z]{2,})+|www\.[\w.-]+(?:\.[a-zA-Z]{2,})+'

    # Regular expression pattern for IP addresses (IPv4 and IPv6)
    ip_pattern = r'\b(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[?[0-9a-fA-F:]+\]?)\b'

    hashes = []
    urls_domains = []
    ips = []

    # Loop through each page and find hashes, URLs/domains, and IPs using regex
    for page_num in range(pdf_document.page_count):
        page = pdf_document.load_page(page_num)
        page_text = page.get_text()

        # Find hashes using regex
        found_hashes = re.findall(hash_pattern, page_text)
        hashes.extend(found_hashes)

        # Find URLs/domains using regex
        found_urls_domains = re.findall(url_pattern, page_text)
        urls_domains.extend(found_urls_domains)

        # Find IPs using regex (using a more comprehensive pattern)
        found_ips = re.findall(ip_pattern, page_text)
        ips.extend(found_ips)

    # Close the PDF document
    pdf_document.close()

    return hashes, urls_domains, ips

def save_data_to_csv(data, column_name, output_file):
    # Create a DataFrame and save the data to a CSV file
    df = pd.DataFrame({column_name: data})
    df.to_csv(output_file, index=False)

if __name__ == "__main__":
    # Replace 'input_file.pdf' with the path to your PDF file
    pdf_file_path = 'input_file.pdf'
    extracted_hashes, extracted_urls_domains, extracted_ips = extract_data_from_pdf(pdf_file_path)

    # Replace 'hashes_output.csv' with the desired output CSV file path for hashes
    save_data_to_csv(extracted_hashes, 'hashes', 'hashes_output.csv')

    # Replace 'urls_domains_output.csv' with the desired output CSV file path for URLs/domains
    save_data_to_csv(extracted_urls_domains, 'urls_domains', 'urls_domains_output.csv')

    # Replace 'ips_output.csv' with the desired output CSV file path for IPs
    save_data_to_csv(extracted_ips, 'ips', 'ips_output.csv')
