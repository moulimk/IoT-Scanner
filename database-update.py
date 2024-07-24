import requests
import sqlite3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

# Define the URL for the IEEE OUI data
url = 'https://standards.ieee.org/develop/regauth/oui/oui.txt'

# Function to fetch the data from the IEEE text file
def fetch_oui_data():
    response = requests.get(url)
    if response.status_code != 200:
        logging.error(f"Failed to fetch data from {url}, status code: {response.status_code}")
        return []

    oui_data = []
    lines = response.text.splitlines()
    for line in lines:
        if '(hex)' in line:
            parts = line.split('(hex)')
            if len(parts) >= 2:
                oui = parts[0].strip()
                company = parts[1].strip()
                oui_data.append((oui, company))
    return oui_data

# Function to create the database and table if it doesn't exist
def create_database():
    conn = sqlite3.connect('oui.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS oui (
            id INTEGER PRIMARY KEY,
            oui TEXT UNIQUE,
            company TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Function to update the database with new data
def update_database(oui_data):
    conn = sqlite3.connect('oui.db')
    cursor = conn.cursor()
    
    for oui, company in oui_data:
        cursor.execute('''
            INSERT OR IGNORE INTO oui (oui, company)
            VALUES (?, ?)
        ''', (oui, company))
    
    conn.commit()
    conn.close()

# Main function to orchestrate the update
def main():
    create_database()
    oui_data = fetch_oui_data()
    if not oui_data:
        logging.error("No data fetched. Exiting.")
        return
    update_database(oui_data)
    logging.info("Database updated successfully.")

if __name__ == "__main__":
    main()
