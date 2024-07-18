from scapy.all import sniff
from device_detection.packet_analysis import analyze_packet

def packet_callback(packet):
    analyze_packet(packet)

def start_passive_scanning():
    print("Starting passive scanning...")
    sniff(prn=packet_callback, store=0)

