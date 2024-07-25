from scapy.all import sniff, IP
from scapy.layers.tls.all import TLS
import logging

def start_encrypted_traffic_detection(interface):
    try:
        sniff(iface=interface, prn=analyze_encrypted_traffic, store=0)
    except Exception as e:
        logging.error(f"Error starting encrypted traffic detection: {e}")

def analyze_encrypted_traffic(packet):
    try:
        if packet.haslayer(TLS):
            ip_address = packet[IP].src if packet.haslayer(IP) else "Unknown IP"
            logging.info(f"Encrypted traffic detected from IP={ip_address}")
    except Exception as e:
        logging.error(f"Error analyzing encrypted traffic: {e}")
