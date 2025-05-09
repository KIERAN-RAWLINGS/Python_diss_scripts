import os
import json
import csv
import nmap
import socket
import subprocess
from datetime import datetime

VULN_DB_FILE = "vulnerabilities.json"
REPORT_CSV = "eol_vulnerability_report.csv"
REPORT_TXT = "eol_vulnerability_report.txt"
EOL_OS_LIST = ["Windows XP", "Windows 7", "Windows 8.1"]

def get_local_subnets():
    try:
        output = subprocess.check_output("ip -4 -o addr | grep -v '127.0.0.1'", shell=True).decode()
        networks = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) > 3:
                ip_interface = parts[3]
                networks.append(ip_interface)
        if not networks:
            print("No available local networks found.")
            return []
        return networks
    except Exception as e:
        print(f"Error getting networks: {e}")
        return []

def choose_network(networks):
    print("\nAvailable Networks:")
    for i, net in enumerate(networks):
        print(f"[{i}] {net}")
    while True:
        try:
            choice = int(input("\nSelect network to scan: "))
            if 0 <= choice < len(networks):
                return networks[choice]
        except:
            pass
        print("Invalid selection. Try again.")

def load_vulnerability_database():
    try:
        with open(VULN_DB_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to load vulnerability DB: {e}")
        return {}

def scan_network(subnet):
    print(f"Scanning network {subnet}...")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=subnet, arguments='-O')
        return nm
    except Exception as e:
        print(f"Nmap scan failed: {e}")
        return None

def match_os(osmatch, vuln_db):
    for eol_os in EOL_OS_LIST:
        if eol_os.lower() in osmatch.lower():
            return eol_os
    return None

def generate_report(devices):
    headers = ['IP', 'Hostname', 'Detected OS', 'CVE', 'Description', 'CVSS Score']
    with open(REPORT_CSV, 'w', newline='') as csvfile, open(REPORT_TXT, 'w') as txtfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)

        txtfile.write(f"EOL Vulnerability Report\nGenerated: {datetime.now()}\n\n")

        for dev in devices:
            for cve, vuln in dev['vulnerabilities'].items():
                row = [dev['ip'], dev['hostname'], dev['os'], cve, vuln['description'],
                       vuln.get('cvss_v3', {}).get('base_score', vuln.get('cvss_v2', {}).get('base_score', 'N/A'))]
                writer.writerow(row)
                txtfile.write(f"{dev['ip']} ({dev['hostname']}) - {dev['os']}\n")
                txtfile.write(f"  {cve}: {vuln['description']}\n")
                txtfile.write(f"  CVSS Score: {row[-1]}\n\n")

    print(f"\nReport saved to {REPORT_CSV} and {REPORT_TXT}")

def main():
    print("=== EOL Vulnerability Scanner ===\n")

    networks = get_local_subnets()
    if not networks:
        return

    subnet = choose_network(networks)

    vuln_db = load_vulnerability_database()
    if not vuln_db:
        return

    scanner = scan_network(subnet)
    if scanner is None:
        return

    devices = []
    for host in scanner.all_hosts():
        try:
            osmatch = scanner[host]['osmatch'][0]['name'] if 'osmatch' in scanner[host] and scanner[host]['osmatch'] else "Unknown"
            matched_os = match_os(osmatch, vuln_db)

            if matched_os:
                hostname = scanner[host].hostname() if scanner[host].hostname() else "Unknown"
                device = {
                    "ip": host,
                    "hostname": hostname,
                    "os": matched_os,
                    "vulnerabilities": vuln_db.get(matched_os, {})
                }
                devices.append(device)
        except Exception as e:
            print(f"Error processing host {host}: {e}")
            continue

    if not devices:
        print("\nNo EOL devices with known vulnerabilities found.")
    else:
        generate_report(devices)

if __name__ == "__main__":
    main()
