from scapy.all import sniff
import logging
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.all import TLS

def start_protocol_analysis(interface):
    try:
        sniff(iface=interface, prn=analyze_protocol, store=0)
    except Exception as e:
        logging.error(f"Error starting protocol analysis: {e}")

def analyze_protocol(packet):
    try:
        if packet.haslayer(HTTPRequest):
            logging.info("HTTP protocol detected")
        elif packet.haslayer(TLS):
            logging.info("TLS/SSL protocol detected")
    except Exception as e:
        logging.error(f"Error analyzing protocol: {e}")
