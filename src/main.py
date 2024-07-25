# main.py

from device_detection.passive_scanner import start_passive_scanning
from ui.app import start_web_ui
from device_detection.traffic_analysis import start_traffic_analysis
from device_detection.encrypted_traffic_detection import start_encrypted_traffic_detection
from device_detection.communication_pattern_analysis import start_communication_pattern_analysis
from device_detection.protocol_analysis import start_protocol_analysis
from device_detection.real_time_monitoring import start_real_time_monitoring

if __name__ == "__main__":
    import threading

    # Replace 'YOUR_INTERFACE_NAME' with the correct network interface name, e.g., 'eth0', 'wlan0', etc.
    interface_name = 'wlxd03745f230d2'

    # Start passive scanning in a separate thread
    scanner_thread = threading.Thread(target=start_passive_scanning)
    scanner_thread.start()

    # Start traffic analysis in a separate thread
    traffic_thread = threading.Thread(target=start_traffic_analysis, args=(interface_name,))
    traffic_thread.start()

    # Start encrypted traffic detection in a separate thread
    encrypted_thread = threading.Thread(target=start_encrypted_traffic_detection, args=(interface_name,))
    encrypted_thread.start()

    # Start communication pattern analysis in a separate thread
    communication_thread = threading.Thread(target=start_communication_pattern_analysis, args=(interface_name,))
    communication_thread.start()

    # Start protocol analysis in a separate thread
    protocol_thread = threading.Thread(target=start_protocol_analysis, args=(interface_name,))
    protocol_thread.start()

    # Start real-time monitoring in a separate thread
    real_time_thread = threading.Thread(target=start_real_time_monitoring, args=(interface_name,))
    real_time_thread.start()

    # Start the web UI
    start_web_ui()
