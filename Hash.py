import pandas as pd
import hashlib

def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

def add_sha256_hash_column(input_file, data_column, output_file):
    # Read the CSV file into a pandas DataFrame
    df = pd.read_csv(input_file)

    # Generate SHA-256 hashes for the values in the specified data_column
    df['sha256_hash'] = df[data_column].apply(generate_sha256_hash)

    # Save the DataFrame with the new column containing the SHA-256 hashes to a new CSV file
    df.to_csv(output_file, index=False)

if __name__ == "__main__":
    # Replace 'input_file.csv' with the path to your input CSV file
    input_csv = "input_file.csv"

    # Replace 'data_column' with the name of the column whose values will be used to generate the SHA-256 hashes
    data_column_to_hash = "data_column"

    # Replace 'output_file.csv' with the desired name for the output CSV file
    output_csv = "output_file.csv"

    add_sha256_hash_column(input_csv, data_column_to_hash, output_csv)
