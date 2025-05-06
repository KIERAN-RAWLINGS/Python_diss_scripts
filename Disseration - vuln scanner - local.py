import nmap
#import scapy.all as scapy
#import requests
import csv
import os
#import time

# Initialize the Nmap scanner with error correction
try:
    nm = nmap.PortScanner()
except Exception as e:
    print(f"Error initializing Nmap: {e}")
    exit(1)

def ensure_directory(directory):
    """
    Ensures the given directory exists, creates it if not.
    This helps in organizing scan results in a specific folder.
    """
    if not os.path.exists(directory):
        os.makedirs(directory)


def discover_devices(network):
    """
    Scans the local network to discover all accessible devices.
    Uses a ping scan to find active hosts in the given network.
    """
    print(f"Discovering devices on {network}...")
    nm.scan(hosts=network, arguments='-sn')  # Ping scan to detect active hosts
    devices = [host for host in nm.all_hosts()]
    print(f"Discovered devices: {devices}")
    return devices


def scan_ports(target):
    """
    Runs a detailed scan for open ports, services, and OS detection.
    Results are exported to a CSV file
    """
    print(f"Scanning open ports on {target}...")
    nm.scan(target, arguments='-sS -sV -O')  # SYN scan, Service version detection, OS detection
    scan_results = []

    for host in nm.all_hosts():
        # Attempts to detect OS information
        os_info = nm[host]["osmatch"][0]["name"] if "osmatch" in nm[host] and nm[host]["osmatch"] else "Unknown"
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service_name = nm[host][proto][port]['name']
                state = nm[host][proto][port]['state']
                scan_results.append([host, port, proto, service_name, state, os_info])
                print(f"Port {port}/{proto}: {service_name} - {state} | OS: {os_info}")

    # Saves scan results to CSV
    ensure_directory("scan_results")
    filename = "scan_results/port_scan_results.csv"
    with open(filename, "w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Host", "Port", "Protocol", "Service", "State", "OS Detected"])
        writer.writerows(scan_results)
    print(f"Port scan results exported to {filename}")


def detect_exploits(target):
    """
    Detects outdated services running on open ports.
    """
    print(f"Checking for outdated services on {target}...")
    nm.scan(target, arguments='-sV')
    exploit_results = []

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]['name']
                version = nm[host][proto][port].get('version', 'Unknown')
                print(f"Checking {service} version {version} on port {port}...")
                exploit_results.append([service, port, version])

    # Saves detected outdated services to CSV
    ensure_directory("scan_results")
    filename = "scan_results/exploit_scan_results.csv"
    with open(filename, "w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Service", "Port", "Detected Version"])
        writer.writerows(exploit_results)
    print(f"Outdated service scan results exported to {filename}")


def automatic_scan(network):
    """
    Runs an automated full scan on all accessible devices including:
    - Open ports and services
    - OS detection
    - Outdated services
    Storing the results for analysis.
    """
    print(f"Starting automated scan on network {network}...")
    devices = discover_devices(network)
    for device in devices:
        scan_ports(device)
        detect_exploits(device)
    print("Automated network scan completed.")

if __name__ == "__main__":
    target_network = "192.168.10.0/24" # Replace with target network ip address
    automatic_scan(target_network)  # Runs detailed automatic scan on all accessible devices