import pandas as pd
import hashlib

def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

def convert_hash_to_sha256(input_file, hash_column, output_file):
    # Read the CSV file into a pandas DataFrame
    df = pd.read_csv(input_file)

    # Generate SHA-256 hashes for each value in the specified hash_column
    df['sha256'] = df[hash_column].apply(generate_sha256_hash)

    # Save the DataFrame with the new "sha256" column to a new CSV file
    df.to_csv(output_file, index=False)

if __name__ == "__main__":
    # Replace 'input_file.csv' with the path to your input CSV file
    input_csv = "input_file.csv"

    # Replace 'hash_column' with the name of the column containing the hash values
    hash_column_to_convert = "hash_column"

    # Replace 'output_file.csv' with the desired name for the output CSV file
    output_csv = "output_file.csv"

    convert_hash_to_sha256(input_csv, hash_column_to_convert, output_csv)
