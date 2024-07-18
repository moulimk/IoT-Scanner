from scapy.layers.l2 import ARP, Ether
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from data.storage import store_device_info
from device_detection.oui_lookup import get_manufacturer

def analyze_packet(packet):
    if packet.haslayer(DHCP):
        mac_address = packet[Ether].src
        ip_address = packet[Ether].src
        manufacturer = get_manufacturer(mac_address)
        store_device_info(mac_address, ip_address, manufacturer)
    elif packet.haslayer(ARP):
        mac_address = packet[ARP].hwsrc
        ip_address = packet[ARP].psrc
        manufacturer = get_manufacturer(mac_address)
        store_device_info(mac_address, ip_address, manufacturer)
    elif packet.haslayer(DNS) and packet[DNS].opcode == 0:  # Standard query
        mac_address = packet[Ether].src
        ip_address = packet[Ether].src
        manufacturer = get_manufacturer(mac_address)
        store_device_info(mac_address, ip_address, manufacturer)
