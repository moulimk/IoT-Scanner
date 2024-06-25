import netifaces as ni
import scapy.all as scapy
import nmap

# Function to load OUI data from Wireshark oui.txt file
def load_oui_data(file_path):
    oui_data = {}
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if '(base 16)' in line:
                parts = line.split('(base 16)')
                if len(parts) == 2:
                    mac_prefix = parts[0].strip()
                    vendor = parts[1].strip()
                    oui_data[mac_prefix] = vendor
    return oui_data

# Load Wireshark OUI data
oui_file_path = 'oui.txt'  # Update with your actual path
oui_data = load_oui_data(oui_file_path)

# Function to lookup vendor based on MAC address
def get_vendor(mac_address):
    mac_prefix = mac_address[:8].upper().replace(':', '')
    return oui_data.get(mac_prefix, 'Unknown')

# Function to detect local network automatically
def detect_local_network():
    # Get the default gateway interface name (assumed to be the interface connected to the network)
    gateway_if = ni.gateways()['default'][ni.AF_INET][1]
    
    # Get IP address and netmask of the interface
    addr_info = ni.ifaddresses(gateway_if)[ni.AF_INET][0]
    ip_address = addr_info['addr']
    netmask = addr_info['netmask']
    
    # Calculate network range in CIDR notation
    network = ip_address + '/' + str(sum(bin(int(x)).count('1') for x in netmask.split('.')))
    return network

# Function to perform ARP scan using scapy
def arp_scan(network_range):
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices_list = []
    for element in answered_list:
        devices_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices_list.append(devices_dict)
    return devices_list

# Function to perform network scan using python-nmap
def perform_network_scan(network_range):
    # Create a port scanner object
    nm = nmap.PortScanner()
    
    # Perform ARP scan using scapy
    arp_result = arp_scan(network_range)
    
    # Get all hosts found in the ARP scan
    total_hosts = len(arp_result)
    scanned_hosts = 0
    
    # Iterate through each device from ARP scan
    for device in arp_result:
        ip_address = device['ip']
        mac_address = device['mac']
        scanned_hosts += 1
        
        # Calculate progress percentage
        progress = (scanned_hosts / total_hosts) * 100
        
        # Perform Nmap scan for the current host
        nm.scan(hosts=ip_address, arguments='-O -sV')  # Adjust arguments as needed
        
        # Print detailed information about the current host
        print(f"Scanning: {ip_address} ({scanned_hosts}/{total_hosts}) [{progress:.2f}%]")
        print(f"Host: {ip_address}")
        
        # Check if vendor information is available
        if 'vendor' in nm[ip_address]:
            print(f"  Vendor: {nm[ip_address]['vendor']}")
        else:
            # If vendor not found in Nmap result, use OUI lookup
            print(f"  Vendor: {get_vendor(mac_address)}")
        
        print(f"  Status: {nm[ip_address].state()}")
        
        # Print OS details if available
        if 'osmatch' in nm[ip_address]:
            for osclass in nm[ip_address]['osmatch']:
                os_family = osclass.get('osfamily', 'Unknown')
                os_gen = osclass.get('osgen', 'Unknown')
                print(f"  OS details: {osclass['name']} {os_family} {os_gen}")
        else:
            print("  OS details: Unknown")
        
        # Print services information if available
        if 'tcp' in nm[ip_address]:
            for port in nm[ip_address]['tcp']:
                service = nm[ip_address]['tcp'][port]
                print(f"  Port {port}: {service['name']} ({service['state']})")
        else:
            print("  No open ports detected")

if __name__ == "__main__":
    # Detect local network automatically
    network_range = detect_local_network()
    print(f"Detected Network Range: {network_range}")
    
    # Perform network scan on detected range
    perform_network_scan(network_range)
