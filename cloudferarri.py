import scapy.all as scapy
import requests
import os
import subprocess
import logging
import hashlib
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Known malware file signatures (example: list of SHA256 hashes)
KNOWN_MALWARE_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e",  # Example hash (placeholder)
    # Add more known hashes here
}

# Function to sniff network packets
def sniff_packets(interface):
    logging.info(f"Starting packet sniffing on interface: {interface}")
    scapy.sniff(iface=interface, store=False, prn=process_packet)

# Function to process each sniffed packet
def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_layer = packet.getlayer(scapy.IP)
        # Check if the packet is related to Cloudflare
        if 'cloudflare' in ip_layer.src or 'cloudflare' in ip_layer.dst:
            logging.warning(f"Potential Cloudflare Tunnel Detected: {ip_layer.src} -> {ip_layer.dst}")
            # Further analysis can be added here

# Function to download a file from a given URL
def download_file(url, dest):
    try:
        response = requests.get(url)
        with open(dest, 'wb') as file:
            file.write(response.content)
        logging.info(f"Downloaded file from {url} to {dest}")
    except Exception as e:
        logging.error(f"Failed to download file from {url}: {e}")

# Function to calculate file hash
def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to analyze a file to determine if it's malicious
def analyze_file(file_path):
    try:
        file_hash = calculate_hash(file_path)
        logging.info(f"File hash: {file_hash}")
        # Check if file hash matches known malware signatures
        if file_hash in KNOWN_MALWARE_HASHES:
            logging.warning(f"Known malware detected: {file_path}")
            return True
        else:
            logging.info(f"File is not recognized as malware: {file_path}")
            # Further heuristic and behavioral analysis can be added here
            return heuristic_analysis(file_path)
    except Exception as e:
        logging.error(f"Error analyzing file {file_path}: {e}")
        return False

# Function to perform heuristic analysis on a file
def heuristic_analysis(file_path):
    logging.info(f"Performing heuristic analysis on {file_path}")
    try:
        # Example heuristic checks
        if "suspicious" in file_path:  # Placeholder for actual checks
            logging.warning(f"Suspicious file detected: {file_path}")
            return True
        # Add more heuristic checks here
        return False
    except Exception as e:
        logging.error(f"Error during heuristic analysis of {file_path}: {e}")
        return False

# Function to remove a malicious file
def remove_malware(file_path):
    try:
        os.remove(file_path)
        logging.info(f"Removed malware file: {file_path}")
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
    except Exception as e:
        logging.error(f"Error removing file {file_path}: {e}")

# Function to terminate a malicious process by name
def terminate_process(process_name):
    try:
        subprocess.run(['pkill', process_name], check=True)
        logging.info(f"Terminated process: {process_name}")
    except subprocess.CalledProcessError:
        logging.error(f"Failed to terminate process: {process_name}")
    except Exception as e:
        logging.error(f"Error terminating process {process_name}: {e}")

# Function to monitor unusual file modifications
def monitor_file_modifications(path):
    logging.info(f"Monitoring file modifications in: {path}")
    before = dict([(f, None) for f in os.listdir(path)])
    while True:
        after = dict([(f, None) for f in os.listdir(path)])
        added = [f for f in after if not f in before]
        removed = [f for f in before if not f in after]
        if added:
            for file in added:
                logging.warning(f"File added: {file}")
                analyze_file(os.path.join(path, file))
        if removed:
            for file in removed:
                logging.warning(f"File removed: {file}")
        before = after

# Main function to integrate all components
def main():
    interface = 'en0'  # Change to the appropriate network interface for macOS
    logging.info("Starting the malware detection and removal tool")
    # Start packet sniffing in a separate thread
    import threading
    sniff_thread = threading.Thread(target=sniff_packets, args=(interface,))
    sniff_thread.start()
    # Start monitoring file modifications
    monitor_file_modifications('/path/to/monitor')  # Change to the path you want to monitor

if __name__ == "__main__":
    main()
