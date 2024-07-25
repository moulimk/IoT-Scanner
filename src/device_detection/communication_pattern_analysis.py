from scapy.all import sniff, IP
import logging

def start_communication_pattern_analysis(interface):
    try:
        sniff(iface=interface, prn=analyze_communication_pattern, store=0)
    except Exception as e:
        logging.error(f"Error starting communication pattern analysis: {e}")

def analyze_communication_pattern(packet):
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            logging.info(f"Communication detected: {src_ip} -> {dst_ip}")
    except Exception as e:
        logging.error(f"Error analyzing communication pattern: {e}")
