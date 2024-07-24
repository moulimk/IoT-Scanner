import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

OUI_DB = {}

def load_oui_database(file_path='oui.txt'):
    logging.info("Loading OUI database from {}".format(file_path))
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if not line.startswith('#') and line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        # Handle extra tab/whitespace
                        prefix = parts[0].strip().upper().replace(':', '-')
                        manufacturer = ' '.join(parts[2:]).strip()
                        OUI_DB[prefix] = manufacturer
        logging.info("Loaded {} entries into OUI database".format(len(OUI_DB)))
        # Print first few entries for verification
        for i, (prefix, manufacturer) in enumerate(OUI_DB.items()):
            if i < 10:
                logging.debug("OUI entry {}: {} -> {}".format(i, prefix, manufacturer))
    except FileNotFoundError:
        logging.error("OUI database file {} not found.".format(file_path))
    except Exception as e:
        logging.error("An error occurred while loading OUI database: {}".format(e))

def get_manufacturer(mac):
    prefix = mac[:8].upper().replace(':', '-')
    logging.debug("Looking up manufacturer for MAC prefix: {}".format(prefix))
    if prefix in OUI_DB:
        manufacturer = OUI_DB[prefix]
        logging.info("Manufacturer found: {} for MAC: {} (prefix: {})".format(manufacturer, mac, prefix))
    else:
        manufacturer = 'Unknown Manufacturer'
        logging.warning("Manufacturer not found for MAC: {} (prefix: {})".format(mac, prefix))
    return manufacturer

# Load the OUI database at the start
load_oui_database()
