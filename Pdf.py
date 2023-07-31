import re
import pandas as pd
import fitz  # PyMuPDF

def extract_hashes_from_pdf(pdf_file):
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

def save_hashes_to_csv(hashes, output_file):
    # Create a DataFrame and save the hashes to a CSV file
    df = pd.DataFrame({'hashes': hashes})
    df.to_csv(output_file, index=False)

if __name__ == "__main__":
    # Replace 'input_file.pdf' with the path to your PDF file
    pdf_file_path = 'input_file.pdf'
    extracted_hashes = extract_hashes_from_pdf(pdf_file_path)

    # Replace 'output_file.csv' with the desired output CSV file path
    output_csv_file = 'output_file.csv'
    save_hashes_to_csv(extracted_hashes, output_csv_file)
