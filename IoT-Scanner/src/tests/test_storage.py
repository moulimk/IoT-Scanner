import unittest
from data.storage import store_device_info

class TestStorage(unittest.TestCase):
    def test_store_device_info(self):
        store_device_info('00:11:22:33:44:55', '192.168.1.1', 'Test Manufacturer')
        # Add assertions to verify the behavior

if __name__ == '__main__':
    unittest.main()
