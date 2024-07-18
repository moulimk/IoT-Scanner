import unittest
from scapy.layers.l2 import Ether, ARP
from device_detection.packet_analysis import analyze_packet

class TestPacketAnalysis(unittest.TestCase):
    def test_analyze_packet_arp(self):
        packet = Ether() / ARP(hwsrc='00:11:22:33:44:55', psrc='192.168.1.1')
        analyze_packet(packet)
        # Add assertions to verify the behavior

if __name__ == '__main__':
    unittest.main()
