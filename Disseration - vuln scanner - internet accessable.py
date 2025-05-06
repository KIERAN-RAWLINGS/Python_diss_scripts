import nmap
import shodan
import csv
import os

"""
Shodan API configuration
"""
SHODAN_API_KEY = "shodan_api_key"
shodan_api = shodan.Shodan(SHODAN_API_KEY)
nm = nmap.PortScanner()


def ensure_directory(directory):
    """
    Error correction - if the stated directory doesn't exist, it creates the directory.
    """
    if not os.path.exists(directory):
        os.makedirs(directory)


def search_shodan_for_vulnerable_devices():
    """
    Searches Shodan for internet accessible devices with known OS vulnerabilities, targeting EOL operating systems.
    Limits results to 500 devices for logical devices
    """
    try:
        print("Searching for vulnerable EOL devices via Shodan...")
        eol_os_list = ["Windows XP", "Windows Vista", "Windows 7", "Windows 8", "Ubuntu 10.04", "Ubuntu 12.04",
                       "Ubuntu 14.04", "Ubuntu 16.04"]
        vulnerable_devices = []

        for os_name in eol_os_list:
            query = f"os:\"{os_name}\" vuln:"
            results = shodan_api.search(query, limit=500)  # Limits the results to 500 devices

            for result in results['matches']:
                if len(vulnerable_devices) >= 500:
                    break
                ip = result['ip_str']
                port = result.get('port', 'Unknown')
                os_info = result.get('os', 'Unknown')
                vulns = result.get('vulns', [])

                print(f"Found EOL device: {ip} | Port: {port} | OS: {os_info} | Vulnerabilities: {vulns}")

                vulnerable_devices.append([ip, port, os_info, ", ".join(vulns)])

        ensure_directory("scan_results")
        filename = "scan_results/internet_vulnerable_eol_devices.csv"

        with open(filename, "w", newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["IP", "Port", "OS", "Vulnerabilities"])
            writer.writerows(vulnerable_devices)

        print(f"EOL vulnerable devices exported to {filename}")

    except shodan.APIError as e:
        print(f"Shodan error: {e}")

if __name__ == "__main__":
    search_shodan_for_vulnerable_devices()  # Calls the shodan search function
