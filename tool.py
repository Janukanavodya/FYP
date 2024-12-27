import os
import nmap
import socket
import vulners
from urllib.parse import urlparse
import re
from time import sleep

# Set your Vulners API key here
API_KEY = "YOUR_API_KEY_HERE"  # Replace with your actual API key

# Function to check for CVEs using Vulners API
def get_cve_info(service_name, version):
    if not API_KEY:
        print("API key not found. Please set your API key.")
        return None

    # Initialize Vulners API
    try:
        vulners_api = vulners.Vulners(api_key=API_KEY)
    except Exception as e:
        print(f"Failed to initialize Vulners API. Check API key! Error: {e}")
        return None

    # Query Vulners for CVEs
    query = f"{service_name} {version}".strip()
    try:
        results = vulners_api.search(query)
        return results
    except Exception as e:
        print(f"Error querying Vulners API: {e}")
        return None

# Function to validate IP address format
def is_valid_ip(ip):
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(ip_pattern.match(ip))

# Function to perform full scan (all 65535 ports) with progress tracking
def scan_target(target_ip):
    print(f"Scanning target: {target_ip}")
    try:
        # Initialize Nmap Scanner
        nm = nmap.PortScanner()
        print("\nStarting full port scan... Please wait.")

        # Total ports to scan (1–65535)
        total_ports = 65535
        scanned_ports = 0  # Counter for progress tracking
        open_ports = []    # List to store open ports

        # Full port scan (1–65535)
        for port in range(1, total_ports + 1):
            # Scan each port with version detection
            nm.scan(hosts=target_ip, arguments=f'-p {port} -sS -sV')

            # Update progress
            scanned_ports += 1
            progress = round((scanned_ports / total_ports) * 100, 2)
            print(f"Scanning port {port}/{total_ports} - Progress: {progress}%", end='\r')

            # Check if the port is open
            for host in nm.all_hosts():
                if port in nm[host]['tcp']:
                    state = nm[host]['tcp'][port]['state']
                    service = nm[host]['tcp'][port].get('name', 'Unknown')
                    version = nm[host]['tcp'][port].get('version', 'Unknown')

                    if state == 'open':  # If port is open, collect data
                        open_ports.append((port, service, version))
                        print(f"\nPort {port} is OPEN - Service: {service}, Version: {version}")

            sleep(0.01)  # Optional: Add slight delay for smooth updates

        # Final scan summary
        print("\nScan completed!")
        if not open_ports:
            print("No open ports found.")
        else:
            print("\nOpen Ports and Services:")
            for port, service, version in open_ports:
                print(f"Port {port} - Service: {service}, Version: {version}")

                # Fetch CVEs for detected services
                cves = get_cve_info(service, version)
                if cves:
                    print(f"  CVEs for {service} {version}:")
                    for cve in cves[:5]:  # Limit to top 5 results
                        print(f"    - {cve['id']}: {cve['title']}")
                else:
                    print(f"  No CVEs found for {service} {version}")

    except Exception as e:
        print(f"Error scanning target {target_ip}: {e}")

# Main function to handle input and start scanning
def main():
    target = input("Enter a website URL or IP address: ").strip()

    # Validate input format
    if is_valid_ip(target):
        print(f"Scanning IP: {target}")
        scan_target(target)
    else:
        # Handle domain names
        if target.startswith("http://") or target.startswith("https://"):
            parsed_url = urlparse(target)
            try:
                ip = socket.gethostbyname(parsed_url.netloc)
                print(f"Scanning {target} (IP: {ip})")
                scan_target(ip)
            except socket.gaierror:
                print("Invalid domain name or DNS resolution failed.")
        else:
            print("Invalid IP address or URL format.")

if __name__ == "__main__":
    main()
