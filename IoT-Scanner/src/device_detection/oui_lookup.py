def load_oui_database():
    oui_dict = {}
    with open('oui.txt', 'r') as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) == 2:
                oui_prefix, manufacturer = parts
                oui_dict[oui_prefix.upper()] = manufacturer
    return oui_dict

oui_database = load_oui_database()

def get_manufacturer(mac_address):
    oui_prefix = mac_address[:8].upper().replace(":", "-")
    return oui_database.get(oui_prefix, "Unknown Manufacturer")
