import sqlite3
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to get the manufacturer from the SQLite database
def get_manufacturer(mac):
    prefix = mac[:8].upper().replace(':', '-')
    
    conn = sqlite3.connect('oui.db')
    cursor = conn.cursor()
    cursor.execute('''SELECT company FROM oui WHERE oui = ?''', (prefix,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        manufacturer = result[0]
    else:
        manufacturer = 'Unknown Manufacturer'
    
    return manufacturer
