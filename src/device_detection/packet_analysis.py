from scapy.layers.l2 import ARP, Ether
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from data.storage import store_device_info, is_device_stored
from device_detection.oui_lookup import get_manufacturer
import logging

def analyze_packet(packet):
    if packet.haslayer(DHCP):
        mac_address = packet[Ether].src
        ip_address = packet[IP].src
        logging.debug("DHCP Packet: MAC={}, IP={}".format(mac_address, ip_address))
        manufacturer = get_manufacturer(mac_address)
        if not is_device_stored(mac_address, ip_address):
            store_device_info(mac_address, ip_address, manufacturer)
    elif packet.haslayer(ARP):
        mac_address = packet[ARP].hwsrc
        ip_address = packet[ARP].psrc
        logging.debug("ARP Packet: MAC={}, IP={}".format(mac_address, ip_address))
        manufacturer = get_manufacturer(mac_address)
        if not is_device_stored(mac_address, ip_address):
            store_device_info(mac_address, ip_address, manufacturer)
    elif packet.haslayer(DNS) and packet[DNS].opcode == 0:  # Standard query
        mac_address = packet[Ether].src
        ip_address = packet[IP].src
        logging.debug("DNS Packet: MAC={}, IP={}".format(mac_address, ip_address))
        manufacturer = get_manufacturer(mac_address)
        if not is_device_stored(mac_address, ip_address):
            store_device_info(mac_address, ip_address, manufacturer)
