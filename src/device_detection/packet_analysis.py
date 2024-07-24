from scapy.layers.l2 import ARP, Ether
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP
from device_detection.oui_lookup import get_manufacturer
from data.storage import store_device_info, is_device_stored
import logging

def analyze_packet(packet):
    mac_address = None
    ip_address = None
    if packet.haslayer(DHCP):
        mac_address = packet[Ether].src
        if packet.haslayer(IP):
            ip_address = packet[IP].src
        logging.debug("DHCP Packet: MAC={}, IP={}".format(mac_address, ip_address))
    elif packet.haslayer(ARP):
        mac_address = packet[ARP].hwsrc
        ip_address = packet[ARP].psrc
        logging.debug("ARP Packet: MAC={}, IP={}".format(mac_address, ip_address))
    elif packet.haslayer(DNS) and packet[DNS].opcode == 0:  # Standard query
        mac_address = packet[Ether].src
        if packet.haslayer(IP):
            ip_address = packet[IP].src
        logging.debug("DNS Packet: MAC={}, IP={}".format(mac_address, ip_address))

    if mac_address:
        manufacturer = get_manufacturer(mac_address)
        store_device_info(mac_address, ip_address, manufacturer)
    else:
        logging.warning("Packet missing MAC or IP: MAC={}, IP={}".format(mac_address, ip_address))
