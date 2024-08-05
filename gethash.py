import hashlib

def calculate_hash(file_path):
    """Calculate the SHA-256 hash of the specified file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None

# Example usage:
file_path = 'path_to_malware_file'
file_hash = calculate_hash(file_path)
if file_hash:
    print(f"The SHA-256 hash of the file is: {file_hash}")
else:
    print("File not found.")
