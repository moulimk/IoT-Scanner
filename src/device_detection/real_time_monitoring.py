from scapy.all import sniff, IP
import logging

def start_real_time_monitoring(interface):
    try:
        sniff(iface=interface, prn=monitor_real_time, store=0)
    except Exception as e:
        logging.error(f"Error starting real-time monitoring: {e}")

def monitor_real_time(packet):
    try:
        if packet.haslayer(IP):
            ip_address = packet[IP].src
            logging.info(f"Real-time activity detected from IP={ip_address}")
    except Exception as e:
        logging.error(f"Error monitoring real-time activity: {e}")
    