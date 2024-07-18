import sqlite3

def init_db():
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS devices
                      (mac_address TEXT, ip_address TEXT, manufacturer TEXT)''')
    conn.commit()
    conn.close()

def store_device_info(mac_address, ip_address, manufacturer):
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO devices (mac_address, ip_address, manufacturer)
                      VALUES (?, ?, ?)''', (mac_address, ip_address, manufacturer))
    conn.commit()
    conn.close()

def get_all_devices():
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute('SELECT mac_address, ip_address, manufacturer FROM devices')
    devices = cursor.fetchall()
    conn.close()
    return devices

init_db()
