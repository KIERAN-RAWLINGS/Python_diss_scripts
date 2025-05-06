import nmap
#import scapy.all as scapy
import scrapy
import requests
import socket
import scapy


def scan_network(network_range):
    scanner = nmap.PortScanner()
    scanner.scan(network_range, arguments='-O')
    devices = []
    for host in scanner.all_hosts():
        os_info = scanner[host]['osmatch'][0]['name'] if scanner[host].has_key('osmatch') else 'Unknown'
        devices.append({'IP': host, 'OS': os_info})
    return devices

def detect_open_ports(target_ip):
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, arguments='-p 1-65535 -T4')
    open_ports = [port for port in scanner[target_ip]['tcp'] if scanner[target_ip]['tcp'][port]['state'] == 'open']
    return open_ports

def detect_outdated_services(target_ip):
    scanner = nmap.PortScanner()
    scanner.scan(target_ip, arguments='-sV')
    outdated_services = []
    for port in scanner[target_ip]['tcp']:
        service = scanner[target_ip]['tcp'][port]['name']
        version = scanner[target_ip]['tcp'][port]['version']
        outdated_services.append({'port': port, 'service': service, 'version': version})
    return outdated_services

def analyze_network_traffic(interface):
    print("Capturing network traffic for suspicious activity...")
    packets = scapy.sniff(iface=interface, count=100)
    for packet in packets:
        if packet.haslayer(scapy.Raw):
            print(f"Suspicious packet detected: {packet.summary()}")

def check_vulnerabilities(service, version):
    cve_api_url = f'https://cve.circl.lu/api/search/{service} {version}'
    response = requests.get(cve_api_url)
    if response.status_code == 200:
        vulnerabilities = response.json()
        return vulnerabilities
    return []

def detect_accessible_subnets():
    scanner = nmap.PortScanner()
    scanner.scan(arguments='-sn')
    subnets = set()
    for host in scanner.all_hosts():
        subnet = '.'.join(host.split('.')[:3]) + '.0/24'
        subnets.add(subnet)
    return list(subnets)

def start_scan(target_ip_range):
    target_network = target_ip_range
    detected_devices = scan_network(target_network)
    for device in detected_devices:
        print(f"Device Found: IP {device['IP']} - OS: {device['OS']}")
        open_ports = detect_open_ports(device['IP'])
        print(f"Open Ports: {open_ports}")
        services = detect_outdated_services(device['IP'])
        for service in services:
            vulnerabilities = check_vulnerabilities(service['service'], service['version'])
            print(f"Service {service['service']} Version {service['version']} - Vulnerabilities: {vulnerabilities}")
    analyze_network_traffic('eth0')

if __name__ == "__main__":
  accessible_subnets = detect_accessible_subnets()
  #print("enter the target subnet")
  #user_input = input(f"Accessible Subnets: {accessible_subnets}")

  #start_scan(user_input)
  temp = "172.16.0.0/16"
  start_scan(temp)