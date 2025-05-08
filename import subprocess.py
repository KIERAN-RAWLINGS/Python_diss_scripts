import json
import csv
import os
import subprocess
import nmap
from datetime import datetime

# Load vulnerability database
def load_vuln_db(filepath="vuln_db.json"):
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Could not load vulnerability database: {e}")
        return {}

# Discover local subnets
def get_local_subnets():
    try:
        result = subprocess.check_output("ip -o -f inet addr show | awk '/scope global/ {print $4}'", shell=True).decode().strip().split('\n')
        return [r for r in result if r]
    except Exception as e:
        print(f"[ERROR] Failed to get subnets: {e}")
        return []

# Let user choose network to scan
def choose_network(subnets):
    print("Available networks to scan:")
    for i, net in enumerate(subnets):
        print(f"{i+1}. {net}")
    try:
        choice = int(input("Select the network to scan (number): ")) - 1
        return subnets[choice]
    except:
        print("[ERROR] Invalid selection.")
        return None

# Scan devices on network
def scan_network(target_net):
    print(f"[INFO] Scanning network: {target_net}")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target_net, arguments='-O')
        devices = []
        for host in nm.all_hosts():
            if 'osmatch' in nm[host]:
                os_info = nm[host]['osmatch'][0]['name'] if nm[host]['osmatch'] else "Unknown"
                devices.append({
                    "ip": host,
                    "os": os_info
                })
        return devices
    except Exception as e:
        print(f"[ERROR] Nmap scanning failed: {e}")
        return []

# Match OS against EOL database
def match_vulnerabilities(devices, vuln_db):
    eol_devices = []
    for device in devices:
        os_name = device["os"]
        for eol_os in vuln_db.keys():
            if eol_os.lower() in os_name.lower():
                device["eol_os"] = eol_os
                device["vulnerabilities"] = vuln_db[eol_os]
                eol_devices.append(device)
                break
    return eol_devices

# Output report
def generate_reports(eol_devices):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = f"vuln_report_{timestamp}.csv"
    txt_path = f"vuln_report_{timestamp}.txt"

    with open(csv_path, "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "OS", "CVE", "Description", "CVSS v2", "CVSS v3"])
        for device in eol_devices:
            for cve, vuln in device["vulnerabilities"].items():
                writer.writerow([
                    device["ip"],
                    device["eol_os"],
                    cve,
                    vuln["description"],
                    vuln.get("cvss_v2", {}).get("base_score", "N/A"),
                    vuln.get("cvss_v3", {}).get("base_score", "N/A")
                ])

    with open(txt_path, "w") as txtfile:
        for device in eol_devices:
            txtfile.write(f"\nDevice: {device['ip']} - {device['eol_os']}\n")
            for cve, vuln in device["vulnerabilities"].items():
                txtfile.write(f"  {cve} - {vuln['description']}\n")
                if "cvss_v2" in vuln:
                    txtfile.write(f"    CVSS v2 Score: {vuln['cvss_v2']['base_score']}\n")
                if "cvss_v3" in vuln:
                    txtfile.write(f"    CVSS v3 Score: {vuln['cvss_v3']['base_score']}\n")
    print(f"[INFO] Report generated: {csv_path}, {txt_path}")

# Main
def main():
    print("== Offline WAN Vulnerability Scanner ==")

    vuln_db = load_vuln_db()
    if not vuln_db:
        return

    subnets = get_local_subnets()
    if not subnets:
        print("[ERROR] No networks found.")
        return

    selected_net = choose_network(subnets)
    if not selected_net:
        return

    devices = scan_network(selected_net)
    if not devices:
        print("[INFO] No devices found.")
        return

    eol_devices = match_vulnerabilities(devices, vuln_db)
    if not eol_devices:
        print("[INFO] No EOL devices found.")
        return

    generate_reports(eol_devices)

if __name__ == "__main__":
    main()
