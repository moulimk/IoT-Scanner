from device_detection.passive_scanner import start_passive_scanning
from ui.app import start_web_ui

if __name__ == "__main__":
    # Start the passive scanning in a separate thread or process
    import threading

    scanner_thread = threading.Thread(target=start_passive_scanning)
    scanner_thread.start()

    # Start the web UI
    start_web_ui()

