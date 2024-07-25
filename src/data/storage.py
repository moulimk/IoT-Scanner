# storage.py

import sqlite3
import logging

def init_db():
    try:
        conn = sqlite3.connect('devices.db')
        cursor = conn.cursor()
        # Check if the device_type column exists
        cursor.execute("PRAGMA table_info(devices)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'device_type' not in columns:
            # Add the device_type column if it doesn't exist
            cursor.execute('ALTER TABLE devices ADD COLUMN device_type TEXT')
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logging.error(f"SQLite error: {e}")

def is_device_stored(mac_address):
    try:
        conn = sqlite3.connect('devices.db')
        cursor = conn.cursor()
        cursor.execute('''SELECT COUNT(*) FROM devices WHERE mac_address = ?''', (mac_address,))
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
    except sqlite3.Error as e:
        logging.error(f"SQLite error: {e}")
        return False

def store_device_info(mac_address, ip_address, manufacturer, device_type):
    try:
        conn = sqlite3.connect('devices.db')
        cursor = conn.cursor()
        if not is_device_stored(mac_address):
            cursor.execute('''
                INSERT INTO devices (mac_address, ip_address, manufacturer, device_type)
                VALUES (?, ?, ?, ?)
            ''', (mac_address, ip_address, manufacturer, device_type))
            logging.info(f"Stored device: MAC={mac_address}, IP={ip_address}, Manufacturer={manufacturer}, Device Type={device_type}")
        else:
            cursor.execute('''
                UPDATE devices SET ip_address = ?, manufacturer = ?, device_type = ? WHERE mac_address = ?
            ''', (ip_address, manufacturer, device_type, mac_address))
            logging.info(f"Updated device: MAC={mac_address}, IP={ip_address}, Manufacturer={manufacturer}, Device Type={device_type}")
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logging.error(f"SQLite error: {e}")

def get_all_devices():
    try:
        conn = sqlite3.connect('devices.db')
        cursor = conn.cursor()
        cursor.execute('SELECT mac_address, ip_address, manufacturer, device_type FROM devices')
        devices = cursor.fetchall()
        conn.close()
        return devices
    except sqlite3.Error as e:
        logging.error(f"SQLite error: {e}")
        return []

# Call the init_db function to initialize the database
init_db()
