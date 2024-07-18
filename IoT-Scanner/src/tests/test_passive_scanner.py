import unittest
from scapy.layers.l2 import Ether, ARP
from device_detection.passive_scanner import packet_callback

class TestPassiveScanner(unittest.TestCase):
    def test_packet_callback(self):
        packet = Ether() / ARP(hwsrc='00:11:22:33:44:55', psrc='192.168.1.1')
        packet_callback(packet)
        # Add assertions to verify the behavior

if __name__ == '__main__':
    unittest.main()
