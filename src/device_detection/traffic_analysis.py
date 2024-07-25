from scapy.all import sniff, IP
import logging

def start_traffic_analysis(interface):
    try:
        sniff(iface=interface, prn=analyze_traffic, store=0)
    except Exception as e:
        logging.error(f"Error starting traffic analysis: {e}")

def analyze_traffic(packet):
    try:
        if packet.haslayer(IP):
            ip_address = packet[IP].src
            logging.info(f"Traffic from IP={ip_address}")
    except Exception as e:
        logging.error(f"Error analyzing traffic: {e}")
