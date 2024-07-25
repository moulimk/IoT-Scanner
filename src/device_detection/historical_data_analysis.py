# historical_data_analysis.py

import sqlite3
from datetime import datetime
import logging

def init_historical_db():
    try:
        conn = sqlite3.connect('historical_data.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS historical_data (
                id INTEGER PRIMARY KEY,
                mac_address TEXT,
                ip_address TEXT,
                activity TEXT,
                timestamp TEXT
            )
        ''')
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logging.error(f"SQLite error: {e}")

def store_historical_data(mac_address, ip_address, activity):
    try:
        conn = sqlite3.connect('historical_data.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO historical_data (mac_address, ip_address, activity, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (mac_address, ip_address, activity, str(datetime.now())))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logging.error(f"SQLite error: {e}")

def get_historical_data():
    try:
        conn = sqlite3.connect('historical_data.db')
        cursor = conn.cursor()
        cursor.execute('SELECT mac_address, ip_address, activity, timestamp FROM historical_data')
        data = cursor.fetchall()
        conn.close()
        return data
    except sqlite3.Error as e:
        logging.error(f"SQLite error: {e}")
        return []

# Initialize the historical database
init_historical_db()
