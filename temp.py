mport nmap
import netifaces
import json
import csv
import os
from datetime import datetime

# Load vulnerability database
def load_vuln_db(filename="vulnerabilities.json"):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load vulnerability database: {e}")
        return {}

# Dynamically detect local subnets
def detect_networks():
    nm = nmap.PortScanner()
    subnets = set()
    available = []

    print("[*] Detecting active interfaces and calculating subnets...")

    for iface in netifaces.interfaces():
        try:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for link in addrs[netifaces.AF_INET]:
                    ip = link.get('addr')
                    netmask = link.get('netmask')
                    if ip and netmask and not ip.startswith('127.'):
                        cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
                        subnet = f"{ip}/{cidr}"
                        subnets.add(subnet)
        except Exception as e:
            print(f"[!] Error processing interface {iface}: {e}")

    print(f"[*] Scanning {len(subnets)} detected subnets for active hosts...")
    for subnet in subnets:
        try:
            nm.scan(hosts=subnet, arguments='-sn')
            if nm.all_hosts():
                available.append(subnet)
        except Exception as e:
            print(f"[!] Error scanning subnet {subnet}: {e}")

    return available

# Detect OS and scan open ports
def scan_devices(subnet, vuln_db):
    nm = nmap.PortScanner()
    print(f"\n[*] Scanning subnet {subnet} for devices and OS info...")
    
    try:
        # Run Nmap with OS detection and SYN port scan (requires sudo)
        nm.scan(hosts=subnet, arguments='-O -sS -T4')
    except Exception as e:
        print(f"[!] Nmap scan failed: {e}")
        return []

    results = []

    for host in nm.all_hosts():
        os_name = "Unknown"
        try:
            if 'osmatch' in nm[host] and nm[host]['osmatch']:
                os_name = nm[host]['osmatch'][0]['name']
        except Exception as e:
            print(f"[!] Could not determine OS for {host}: {e}")

        is_eol = os_name in vuln_db
        vulnerabilities = vuln_db.get(os_name, {})

        open_ports = []
        try:
            if 'tcp' in nm[host]:
                for port in nm[host]['tcp']:
                    service = nm[host]['tcp'][port]['name']
                    open_ports.append(f"{port}/{service}")
        except Exception as e:
            print(f"[!] Error retrieving open ports for {host}: {e}")

        device_info = {
            "ip": host,
            "os": os_name,
            "eol": is_eol,
            "vulns": vulnerabilities,
            "open_ports": open_ports
        }

        results.append(device_info)

    return results

# Generate CSV and TXT report
def generate_report(results, output_prefix="report"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = f"{output_prefix}_{timestamp}.csv"
    txt_file = f"{output_prefix}_{timestamp}.txt"

    with open(csv_file, 'w', newline='') as csvfile, open(txt_file, 'w') as txtfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP Address', 'Detected OS', 'EOL', 'Open Ports', 'Vulnerabilities'])

        for device in results:
            vuln_summary = "; ".join([f"{cve}: {info['description']}" for cve, info in device['vulnerabilities'].items()]) if device['eol'] else "N/A"
            ports_summary = ", ".join([f"{p}/{s}" for p, s, _ in device['open_ports']])

            writer.writerow([device['host'], device['os'], device['eol'], ports_summary, vuln_summary])

            txtfile.write(f"\nHost: {device['host']}\n")
            txtfile.write(f"OS: {device['os']}\n")
            txtfile.write(f"EOL: {device['eol']}\n")
            txtfile.write(f"Open Ports: {ports_summary}\n")
            if device['eol']:
                txtfile.write("Vulnerabilities:\n")
                for cve, info in device['vulnerabilities'].items():
                    txtfile.write(f"  {cve}: {info['description']}\n")
            txtfile.write("-" * 60 + "\n")

    print(f"[+] Report saved as {csv_file} and {txt_file}")

# Main execution flow
def main():
    vuln_db = load_vuln_db("vuln_db.json")
    if not vuln_db:
        print("[!] No vulnerabilities loaded. Exiting.")
        return

    networks = detect_networks()
    if not networks:
        print("[!] No active local networks found. Exiting.")
        return

    print("\n[+] Available Networks:")
    for i, net in enumerate(networks):
        print(f"{i + 1}: {net}")

    choice = input("Select a network to scan (1-{0}): ".format(len(networks)))
    try:
        subnet = networks[int(choice) - 1]
    except:
        print("[!] Invalid selection. Exiting.")
        return

    results = scan_devices(subnet, vuln_db)
    if results:
        generate_report(results)
    else:
        print("[!] No devices found or scan failed.")

if __name__ == "__main__":
    main()
