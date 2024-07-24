import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

OUI_DB = {}

def load_oui_database(file_path='oui.txt'):
    logging.info("Loading OUI database from {}".format(file_path))
    try:
        with open(file_path, 'r') as f:
            current_prefix = None
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split()
                if len(parts) == 3 and parts[2] == '(hex)':
                    current_prefix = parts[0].upper().replace('-', ':')
                elif current_prefix and len(parts) > 0:
                    manufacturer = ' '.join(parts)
                    OUI_DB[current_prefix] = manufacturer
                    current_prefix = None

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
load_oui_database('oui.txt')
