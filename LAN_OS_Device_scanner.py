import nmap
import json
import csv
import netifaces
import os

# Get the directory where the script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VULN_DB_PATH = os.path.join(SCRIPT_DIR, "vulnerabilities.json")
OUTPUT_TEXT = "eol_report.txt"
OUTPUT_CSV = "eol_report.csv"
EOL_OS_LIST = ["Windows XP", "Windows 7", "Windows 8.1", "Ubuntu 14.04"]

def load_vulnerability_db(path):
    with open(path, 'r') as f:
        return json.load(f)

def get_network_interfaces():
    interfaces = netifaces.interfaces()
    networks = []
    for iface in interfaces:
        if netifaces.AF_INET in netifaces.ifaddresses(iface):
            ip_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
            ip = ip_info.get('addr')
            netmask = ip_info.get('netmask')
            if ip and netmask:
                cidr = f"{ip}/{netmask_to_cidr(netmask)}"
                networks.append((iface, cidr))
    return networks

def netmask_to_cidr(netmask):
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def choose_network_interface(networks):
    print("Available Network Interfaces:")
    for i, (iface, cidr) in enumerate(networks):
        print(f"{i + 1}. {iface} - {cidr}")
    choice = int(input("Select the network to scan: ")) - 1
    return networks[choice][1]

def scan_network(network_range):
    scanner = nmap.PortScanner()
    print(f"Scanning {network_range} for devices... (this may take a while)")
    scanner.scan(hosts=network_range, arguments='-O')
    return scanner

def identify_os(scan_data):
    os_results = {}
    for host in scan_data.all_hosts():
        if 'osmatch' in scan_data[host]:
            os_matches = scan_data[host]['osmatch']
            if os_matches:
                os_name = os_matches[0]['name']
                os_results[host] = os_name
            else:
                os_results[host] = "Unknown"
        else:
            os_results[host] = "Unknown"
    return os_results

def match_eol_and_vulns(os_results, vuln_db):
    report = []
    for ip, os_name in os_results.items():
        matched_os = next((eol for eol in EOL_OS_LIST if eol.lower() in os_name.lower()), None)
        if matched_os and matched_os in vuln_db:
            vulns = vuln_db[matched_os]
            report.append({
                "ip": ip,
                "os": matched_os,
                "vulns": vulns
            })
    return report

def write_reports(report):
    with open(OUTPUT_TEXT, 'w') as txt, open(OUTPUT_CSV, 'w', newline='') as csvf:
        csv_writer = csv.writer(csvf)
        csv_writer.writerow(["IP", "OS", "CVE", "Description", "CVSSv2"])
        for entry in report:
            txt.write(f"\nDevice IP: {entry['ip']}\nDetected OS: {entry['os']}\nVulnerabilities:\n")
            for cve, details in entry['vulns'].items():
                desc = details.get("description", "")
                cvss2_score = details.get('cvss_v2', {}).get('base_score', 'N/A')
                cvss2_vector = details.get('cvss_v2', {}).get('vector', '')
                txt.write(f"  - {cve}: {desc}\n    CVSSv2: {cvss2_score} ({cvss2_vector})\n")
                csv_writer.writerow([entry['ip'], entry['os'], cve, desc, f"{cvss2_score} ({cvss2_vector})"])

    print(f"\nReports generated: {OUTPUT_TEXT}, {OUTPUT_CSV}")

def main():
    if not os.path.exists(VULN_DB_PATH):
        print(f"Error: Vulnerability database {VULN_DB_PATH} not found.")
        return

    vuln_db = load_vulnerability_db(VULN_DB_PATH)
    networks = get_network_interfaces()

    if not networks:
        print("No available network interfaces found.")
        return

    selected_network = choose_network_interface(networks)
    scan_result = scan_network(selected_network)
    os_info = identify_os(scan_result)
    report = match_eol_and_vulns(os_info, vuln_db)
    write_reports(report)

if __name__ == "__main__":
    main()
