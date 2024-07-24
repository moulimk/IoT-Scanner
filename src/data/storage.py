import sqlite3

def init_db():
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS devices
                      (mac_address TEXT PRIMARY KEY, ip_address TEXT, manufacturer TEXT)''')
    conn.commit()
    conn.close()

def is_device_stored(mac_address):
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute('''SELECT COUNT(*) FROM devices WHERE mac_address = ?''', (mac_address,))
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0

def store_device_info(mac_address, ip_address, manufacturer):
    if not is_device_stored(mac_address):
        conn = sqlite3.connect('devices.db')
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO devices (mac_address, ip_address, manufacturer)
                          VALUES (?, ?, ?)''', (mac_address, ip_address, manufacturer))
        conn.commit()
        conn.close()
        print("Stored device: MAC={}, IP={}, Manufacturer={}".format(mac_address, ip_address, manufacturer))
    else:
        conn = sqlite3.connect('devices.db')
        cursor = conn.cursor()
        cursor.execute('''UPDATE devices SET ip_address = ?, manufacturer = ? WHERE mac_address = ?''', 
                       (ip_address, manufacturer, mac_address))
        conn.commit()
        conn.close()
        print("Updated device: MAC={}, IP={}, Manufacturer={}".format(mac_address, ip_address, manufacturer))

def get_all_devices():
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute('SELECT mac_address, ip_address, manufacturer FROM devices')
    devices = cursor.fetchall()
    conn.close()
    return devices

init_db()
