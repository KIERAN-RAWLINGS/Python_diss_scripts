#####################
# EOL device scanner using Shodan API
#####################

# imports the needed libraries
from datetime import datetime
import shodan
import csv
import socket
import time

# stores the Shodan API key
SHODAN_API_KEY = 'Shodan_API_Key'

# Known End-of-Life (EOL) operating systems to target
# list of EOL operating systems
EOL_OS_KEYWORDS = [
    "Windows XP", "Windows 7", "Windows Server 2003", "Windows Server 2008",
    "CentOS 6", "CentOS 5", "Ubuntu 14.04", "Ubuntu 12.04", "Debian 8", "Debian 7",
    "Red Hat 6", "Red Hat 5", "macOS 10.13", "macOS 10.12"
]
# List of supported operating systems
SUPPORTED_OS_KEYWORDS = [
    "Windows 11", "Windows 10", "Ubuntu 20.04", "Ubuntu 22.04"]

# Search filters for the Shodan API
SEARCH_FILTERS = 'os:"Windows" OR os:"Linux"'

# Checks if an OS string indicates an EOL system or an supported OS.
def is_eol_os(os_string):
    return any(eol_os in os_string for eol_os in EOL_OS_KEYWORDS) and not any( 
        supported_os in os_string for supported_os in SUPPORTED_OS_KEYWORDS
    )

# Actively test whether the given IP and port are reachable
def is_port_open(ip, port, timeout=2): # Sets a timeout for the connection
    try:
        with socket.create_connection((ip, port), timeout=timeout): # Attempts to create a socket connection
            return True
    except Exception: # Error handling for connection issues
        return False

def main():
    # Initialises the Shodan API client
    api = shodan.Shodan(SHODAN_API_KEY)

    # Timestamps the csv and txt files
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_file = f"eol_devices_active_{timestamp}.txt"
    csv_file = f"eol_devices_active_{timestamp}.csv"

    print("Starting passive scan using Shodan...")

    try:
        # Search Shodan's database with specified filters
        results = api.search(SEARCH_FILTERS, limit=1000) # Limits the results to 1000 items
        print(f"Shodan returned {len(results['matches'])} results.")

        # Open report files for writing
        with open(txt_file, 'w') as txt, open(csv_file, 'w', newline='') as csvf: # opens the files for writing
            writer = csv.writer(csvf) # creates a CSV writer object
            # CSV header row
            writer.writerow(["IP", "Port", "Hostnames", "Organization", "OS", "CVE ID", "CVSS Score", "Summary"]) 

            # Process each matched host from Shodan results
            for match in results['matches']:
                os_info = match.get('os', '')
                if os_info and is_eol_os(os_info):
                    ip = match.get('ip_str', 'N/A')
                    port = match.get('port', None)

                    # Skip if port is not provided
                    if not port:
                        continue

                    print(f"Checking active status of {ip}:{port}...")

                    # Actively test if the device is live by attempting a connection
                    if not is_port_open(ip, port):
                        print(f"[-] {ip}:{port} not reachable") 
                        continue  # Skip inactive or unreachable hosts

                    print(f"[+] {ip}:{port} is active") # 

                    # Extract additional metadata for reporting
                    hostnames = ','.join(match.get('hostnames', []))
                    org = match.get('org', 'N/A')

                    # Checks if vulnerabilities (CVEs) are present in the EOL device
                    if 'vulns' in match:
                        for cve in match['vulns']:
                            try:
                                # Looks up CVSS and summary using Shodan helper
                                cve_info = shodan.helpers.cve_info(cve)
                                cvss = cve_info.get('cvss', 'N/A')
                                summary = cve_info.get('summary', 'N/A')
                            except Exception:
                                cvss = 'N/A'
                                summary = 'Unable to fetch details'

                            # Logs the results to both TXT and CSV files
                            line = f"[{ip}:{port}] {os_info} | {cve} | CVSS: {cvss} | {summary}" 
                            txt.write(line + "\n")
                            print(line)
                            writer.writerow([ip, port, hostnames, org, os_info, cve, cvss, summary])
                    else:
                        # No vulnerabilities found for the host
                        line = f"[{ip}:{port}] {os_info} | No vulnerabilities found" 
                        txt.write(line + "\n")
                        print(line)
                        writer.writerow([ip, port, hostnames, org, os_info, "None", "", ""])

                    # Sleep to avoid hitting rate limits
                    time.sleep(0.5)

        print(f"\nReports saved: {csv_file}, {txt_file}")

    except shodan.APIError as e: # Error handling for Shodan API issues
        print(f"Shodan API error: {e}") # Informs the user of the error

if __name__ == "__main__":
    main() # calls the main function