#################################
# LAN OS Network Scanner
#################################

# Imports needed libraries
import nmap
import netifaces
import json
import csv
import os
from datetime import datetime

# Load vulnerability database
def load_vuln_db(filename="vuln_db.json"):
    try:
        # Open the JSON file containing the vulnerability information
        with open(filename, 'r') as f:
            return json.load(f)  # Parse and return the data as a Python dictionary
    except Exception as e:
        # If the file cannot be loaded, print an error message and return an empty dictionary
        print(f"Vulnerability database Failed to load: {e}")
        return {}

# Dynamically detect local subnets
def detect_networks():
    nm = nmap.PortScanner()  # Initialize the Nmap port scanner
    subnets = set()  # Set to hold unique subnets
    available = []  # List to hold subnets with active hosts

    print("Detecting active interfaces and calculating subnets")

    # Iterate through all the network interfaces on the machine
    for iface in netifaces.interfaces():
        try:
            # Get the addresses for the current network interface
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:  # Ensure there's an IPv4 address
                for link in addrs[netifaces.AF_INET]:
                    ip = link.get('addr')  # Get the IP address of the interface
                    netmask = link.get('netmask')  # Get the netmask for the interface
                    if ip and netmask and not ip.startswith('127.'):  # Ignore loopback addresses
                        # Calculate the CIDR notation from the netmask
                        cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
                        subnet = f"{ip}/{cidr}"  # Create the subnet string in CIDR format
                        subnets.add(subnet)  # Add the subnet to the set (unique subnets)
        except Exception as e:
            # If there's an error processing the interface, print the error message
            print(f"Error processing interface {iface}: {e}")

    print(f"[*] Scanning {len(subnets)} detected subnets for active hosts...")
    # Iterate through each subnet and perform a Nmap scan to find active hosts
    for subnet in subnets:
        try:
            nm.scan(hosts=subnet, arguments='-sn')  # Run a ping scan to detect active hosts
            if nm.all_hosts():  # If there are any hosts found in the subnet
                available.append(subnet)  # Add the subnet to the list of available subnets
        except Exception as e:
            # If an error occurs during the scan, print the error message
            print(f"Error scanning subnet {subnet}: {e}")

    return available  # Return the list of available subnets with active hosts

def scan_devices(subnet, vuln_db):
    nm = nmap.PortScanner()
    print(f"Scanning subnet {subnet} for devices")

    try:
        nm.scan(hosts=subnet, arguments='-O --osscan-guess --max-os-tries 5 -sS -sV')
    except Exception as e:
        print(f"Error scanning subnet {subnet}: {e}")
        return []

    results = []

    for host in nm.all_hosts():
        os_name = "Unknown"
        eol_vulns = {}

        # Try primary OS match
        if 'osmatch' in nm[host] and nm[host]['osmatch']:
            os_match = nm[host]['osmatch'][0]
            os_name = os_match['name']
        elif 'osclass' in nm[host] and nm[host]['osclass']:
            os_families = [c['osfamily'] for c in nm[host]['osclass'] if 'osfamily' in c]
            if os_families:
                os_name = os_families[0]

        # Normalize known Windows and Linux versions
        if 'windows' in os_name.lower():
            lower = os_name.lower()
            if 'xp' in lower:
                os_name = "Windows XP"
            elif '2003' in lower:
                os_name = "Windows Server 2003"
            elif 'windows 7' in lower or '2008' in lower:
                os_name = "Windows 7"
            elif '6.3' in lower or 'windows 8.1' in lower:
                os_name = "Windows 8.1"
            elif '6.2' in lower or 'windows 8' in lower:
                os_name = "Windows 8"
            elif '10.0' in lower or 'windows 10' in lower:
                os_name = "Windows 10"
            elif 'windows 11' in lower or '10.0.22' in lower:
                os_name = "Windows 11"

        elif 'ubuntu' in os_name.lower():
            if '24.04' in os_name:
                os_name = "Ubuntu 24.04"
            elif '22.04' in os_name:
                os_name = "Ubuntu 22.04"
            elif '20.04' in os_name:
                os_name = "Ubuntu 20.04"
            elif '18.04' in os_name:
                os_name = "Ubuntu 18.04"

        # SMB fallback for Windows
        if os_name == "Unknown" or os_name.startswith("Windows"):
            try:
                smb_nm = nmap.PortScanner()
                smb_nm.scan(hosts=host, arguments='-p 445 --script smb-os-discovery')
                smb_output = smb_nm[host].get('hostscript', [])
                if smb_output:
                    output_text = smb_output[0].get('output', '').lower()

                    if "windows 6.1" in output_text:
                        os_name = "Windows 7"
                    elif "windows 6.3" in output_text:
                        os_name = "Windows 8.1"
                    elif "windows 6.2" in output_text:
                        os_name = "Windows 8"
                    elif "windows 10" in output_text or "10.0" in output_text:
                        os_name = "Windows 10"
                    elif "windows xp" in output_text:
                        os_name = "Windows XP"
                    elif "windows server 2003" in output_text:
                        os_name = "Windows Server 2003"
            except Exception as e:
                print(f"[DEBUG] SMB OS detection failed on {host}: {e}")

        # Match EOL vulnerabilities
        for known_os in vuln_db:
            if known_os.lower() in os_name.lower():
                eol_vulns = vuln_db[known_os]
                break

        # Debug unknown
        if os_name == "Unknown":
            print(f"\n[DEBUG] Raw Nmap fingerprint for host {host}:")
            if 'osmatch' in nm[host]:
                print(json.dumps(nm[host]['osmatch'], indent=2))
            elif 'osclass' in nm[host]:
                print(json.dumps(nm[host]['osclass'], indent=2))
            else:
                print("  No OS fingerprint available.")

        open_ports = []
        if 'tcp' in nm[host]:
            for port in nm[host]['tcp']:
                service = nm[host]['tcp'][port].get('name', 'unknown')
                product = nm[host]['tcp'][port].get('product', 'unknown')
                open_ports.append((port, service, product))

        results.append({
            'host': host,
            'os': os_name,
            'eol': bool(eol_vulns),
            'vulnerabilities': eol_vulns,
            'open_ports': open_ports
        })

    return results


# Generate CSV and TXT report
def generate_report(results, output_prefix="report"):
    # Create a timestamp to include in the filename for uniqueness
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = f"{output_prefix}_{timestamp}.csv"  # CSV filename
    txt_file = f"{output_prefix}_{timestamp}.txt"  # TXT filename

    # Open both CSV and TXT files for writing
    with open(csv_file, 'w', newline='') as csvfile, open(txt_file, 'w') as txtfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP Address', 'Detected OS', 'EOL', 'Open Ports', 'Vulnerabilities'])  # Write the header row

        # Iterate through the results and write to the CSV and TXT files
        for device in results:
            # Create a summary of vulnerabilities if the OS is EOL
            vuln_summary = "; ".join([f"{cve}: {info['description']}" for cve, info in device['vulnerabilities'].items()]) if device['eol'] else "N/A"
            # Create a summary of open ports
            ports_summary = ", ".join([f"{p}/{s}" for p, s, _ in device['open_ports']])

            # Write the device information to the CSV file
            writer.writerow([device['host'], device['os'], device['eol'], ports_summary, vuln_summary])

            # Write detailed information to the TXT file
            txtfile.write(f"\nHost: {device['host']}\n")
            txtfile.write(f"OS: {device['os']}\n")
            txtfile.write(f"EOL: {device['eol']}\n")
            txtfile.write(f"Open Ports: {ports_summary}\n")
            if device['eol']:
                txtfile.write("Vulnerabilities:\n")
                for cve, info in device['vulnerabilities'].items():
                    txtfile.write(f"  {cve}: {info['description']}\n")
            txtfile.write("-" * 60 + "\n")

    # Print a message indicating where the reports are saved
    print(f"Report saved as {csv_file} and {txt_file}")

# Main execution flow
def main():
    # Load the vulnerability database
    vuln_db = load_vuln_db("vulnerabilities.json")
    if not vuln_db:
        # If the vulnerability database is empty, print an error and exits
        print("Vulnerabilities database failed to load")
        return

    # Detects the active networks (subnets) on the local machine
    networks = detect_networks()
    if not networks:
        # If no active networks are found, print an error and exit
        print("No active local networks found")
        return

    # Print the available networks for the user to choose from
    print("\nAvailable Networks:")
    for i, net in enumerate(networks):
        print(f"{i + 1}: {net}")

    # Prompt the user to select a network to scan
    choice = input("Select a network to scan (1-{0}): ".format(len(networks)))
    try:
        # Convert the user's input to the corresponding subnet
        subnet = networks[int(choice) - 1]
    except:
        # If the input is invalid, print an error and exit
        print("Invalid selection. Exiting.")
        return

    # Scan the selected subnet for devices and vulnerabilities
    results = scan_devices(subnet, vuln_db)
    if results:
        # If devices are found, generate the report
        generate_report(results)
    else:
        # If no devices are found, print an error message
        print("No devices found or scan failed.")

if __name__ == "__main__":
    main()  # Call the main function to start the program
