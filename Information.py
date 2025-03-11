import socket
import platform
import requests
import os
import json
import nmap
import time

# Function to get basic device information
def get_device_info():
    device_info = {}
    device_info['hostname'] = socket.gethostname()
    device_info['os'] = platform.system() + " " + platform.release()
    device_info['ip_address'] = socket.gethostbyname(socket.gethostname())
    
    return device_info

# Function to get public IP address and location info using a geolocation API
def get_public_ip_info():
    ip_info = {}
    try:
        # Get public IP
        ip_response = requests.get("https://api.ipify.org?format=json")
        ip_info['public_ip'] = ip_response.json().get("ip")
        
        # Get geographical location of public IP
        location_response = requests.get(f"http://ip-api.com/json/{ip_info['public_ip']}?fields=country,regionName,city,lat,lon")
        location_data = location_response.json()
        
        ip_info['country'] = location_data.get('country', 'Unknown')
        ip_info['region'] = location_data.get('regionName', 'Unknown')
        ip_info['city'] = location_data.get('city', 'Unknown')
        ip_info['latitude'] = location_data.get('lat', 'Unknown')
        ip_info['longitude'] = location_data.get('lon', 'Unknown')
        
    except requests.RequestException as e:
        print(f"Error getting IP information: {e}")
    
    return ip_info

# Function to scan for open ports and services using nmap
def scan_open_ports(target_ip):
    scanner = nmap.PortScanner()
    open_ports = []

    try:
        # Perform a simple port scan to detect open ports (1-1024)
        scanner.scan(target_ip, '1-1024')
        
        for proto in scanner[target_ip].all_protocols():
            lport = scanner[target_ip][proto].keys()
            for port in lport:
                state = scanner[target_ip][proto][port]['state']
                if state == "open":
                    open_ports.append(port)
        
    except Exception as e:
        print(f"Error scanning ports: {e}")
    
    return open_ports

# Function to identify known vulnerabilities using the open ports (basic)
def identify_exploits(open_ports):
    known_exploits = {
        21: "FTP - Anonymous Login Vulnerability",
        22: "SSH - Default Passwords",
        23: "Telnet - Cleartext Passwords",
        80: "HTTP - SQL Injection",
        443: "HTTPS - SSL Vulnerabilities",
        3389: "RDP - Brute Force Vulnerabilities"
        # Add more exploits based on port numbers here
    }

    exploits_found = {}
    for port in open_ports:
        if port in known_exploits:
            exploits_found[port] = known_exploits[port]
    
    return exploits_found

# Main function that gathers and outputs all information
def main():
    print("Starting information gathering...\n")
    
    # Device information
    device_info = get_device_info()
    print("Device Information:")
    print(f"Hostname: {device_info['hostname']}")
    print(f"Operating System: {device_info['os']}")
    print(f"Local IP Address: {device_info['ip_address']}")
    
    # Public IP and Location information
    public_ip_info = get_public_ip_info()
    print("\nPublic IP Information:")
    print(f"Public IP: {public_ip_info.get('public_ip')}")
    print(f"Country: {public_ip_info.get('country')}")
    print(f"Region: {public_ip_info.get('region')}")
    print(f"City: {public_ip_info.get('city')}")
    print(f"Latitude: {public_ip_info.get('latitude')}")
    print(f"Longitude: {public_ip_info.get('longitude')}")
    
    # Scan for open ports
    print("\nScanning for open ports...")
    open_ports = scan_open_ports(device_info['ip_address'])
    print(f"Open Ports Found: {open_ports}")
    
    # Identify potential exploits based on open ports
    exploits = identify_exploits(open_ports)
    if exploits:
        print("\nPotential Exploits Found:")
        for port, exploit in exploits.items():
            print(f"Port {port}: {exploit}")
    else:
        print("\nNo known exploits found.")
    
    print("\nInformation gathering complete.")

# Run the script
if __name__ == "__main__":
    main()
