import os
import netifaces as ni
import scapy.all as scapy
import nmap
from concurrent.futures import ThreadPoolExecutor

def detect_local_network():
    """Automatically detect the local network range."""
    gateway_if = ni.gateways()['default'][ni.AF_INET][1]
    addr_info = ni.ifaddresses(gateway_if)[ni.AF_INET][0]
    ip_address = addr_info['addr']
    netmask = addr_info['netmask']
    network = ip_address + '/' + str(sum(bin(int(x)).count('1') for x in netmask.split('.')))
    return network

def arp_scan(network_range):
    """Perform an ARP scan over the specified network range using Scapy."""
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]

def load_vendor_dictionary(oui_file_path):
    """Load the vendor dictionary from the OUI file."""
    vendor_dict = {}
    try:
        with open(oui_file_path, "r", encoding='utf-8') as file:
            for line in file:
                if "(base 16)" in line:
                    parts = line.split("(base 16)")
                    key = parts[0].strip().replace('-', ':').lower()
                    vendor = parts[1].strip()
                    vendor_dict[key[:8]] = vendor
    except FileNotFoundError:
        print(f"Error: The file {oui_file_path} was not found.")
    except UnicodeDecodeError as e:
        print(f"Error decoding file {oui_file_path}: {e}")
    return vendor_dict

def perform_device_profiling(device, nm, vendor_dict):
    """Use nmap to profile a device and enrich the data with vendor information."""
    ip_address = device['ip']
    try:
        nm.scan(hosts=ip_address, arguments='-O -sV')  # Adjust arguments as needed
        device_info = {
            "IP": ip_address,
            "MAC": device.get('mac', 'N/A'),
            "Vendor": vendor_dict.get(device['mac'][:8].lower(), 'Unknown')
        }
        return device_info
    except Exception as e:
        return {"IP": ip_address, "Error": str(e)}

def main():
    # Detect the network range
    network_range = detect_local_network()
    print(f"Detected Network Range: {network_range}")
    
    # Perform the ARP scan
    devices = arp_scan(network_range)
    print(f"Detected devices: {devices}")
    
    # Load the OUI database
    base_dir = os.path.dirname(os.path.abspath(__file__))
    oui_file_path = os.path.join(base_dir, 'oui.txt')
    vendor_dict = load_vendor_dictionary(oui_file_path)
    
    # Setup Nmap scanner
    nm = nmap.PortScanner()
    
    # Perform device profiling
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(lambda device: perform_device_profiling(device, nm, vendor_dict), devices))
    
    # Print results
    for result in results:
        print(result)

if __name__ == "__main__":
    main()
