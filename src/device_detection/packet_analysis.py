# packet_analysis.py

from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from device_detection.oui_lookup import get_manufacturer
from data.storage import store_device_info, is_device_stored
from historical_data_analysis import store_historical_data
import logging

def identify_device(packet):
    if packet.haslayer(HTTPRequest):
        return 'HTTP Client'
    elif packet.haslayer(HTTPResponse):
        return 'HTTP Server'
    # Add more layers and heuristics for deeper fingerprinting
    return 'Unknown Device'

def analyze_packet(packet):
    mac_address = None
    ip_address = None
    if packet.haslayer(DHCP):
        mac_address = packet[Ether].src
        if packet.haslayer(IP):
            ip_address = packet[IP].src
    elif packet.haslayer(ARP):
        mac_address = packet[ARP].hwsrc
        ip_address = packet[ARP].psrc
    elif packet.haslayer(DNS) and packet[DNS].opcode == 0:  # Standard query
        mac_address = packet[Ether].src
        if packet.haslayer(IP):
            ip_address = packet[IP].src

    if mac_address:
        manufacturer = get_manufacturer(mac_address)
        device_type = identify_device(packet)
        if manufacturer != 'Unknown Manufacturer':
            store_device_info(mac_address, ip_address, manufacturer, device_type)
            store_historical_data(mac_address, ip_address, f"Detected {device_type}")  # Store historical data
            logging.info(f"Stored/Updated device: MAC={mac_address}, IP={ip_address}, Manufacturer={manufacturer}, Device Type={device_type}")
    else:
        logging.debug(f"Packet missing MAC or IP: {packet.summary()}")
