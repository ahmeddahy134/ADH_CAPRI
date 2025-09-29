import subprocess
import re
import logging

logging.basicConfig(filename="logs/network_tool.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def get_mac_address(interface):
    try:
        ifconfig_result = subprocess.check_output(["ifconfig", interface], stderr=subprocess.DEVNULL).decode("utf-8")
        mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
        if mac_address_search_result:
            return mac_address_search_result.group(0)
        else:
            print("[-] Could not read MAC address")
            logging.error(f"Could not read MAC address for {interface}")
            return None
    except subprocess.CalledProcessError:
        print(f"[-] Interface {interface} not found")
        logging.error(f"Interface {interface} not found")
        return None

def change_mac(interface, new_mac):
    try:
        if not re.match(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$", new_mac):
            raise ValueError("Invalid MAC address format")
        
        print(f"[+] Changing MAC address for {interface} to {new_mac}")
        logging.info(f"Changing MAC address for {interface} to {new_mac}")
        subprocess.call(["ifconfig", interface, "down"], stderr=subprocess.DEVNULL)
        subprocess.call(["ifconfig", interface, "hw", "ether", new_mac], stderr=subprocess.DEVNULL)
        subprocess.call(["ifconfig", interface, "up"], stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        print(f"[-] MAC change failed: {e}")
        logging.error(f"MAC change failed for {interface}: {e}")
        return False

def run_mac_changer(interface, new_mac):
    current_mac = get_mac_address(interface)
    if not current_mac:
        print(f"[-] Could not read current MAC for {interface}")
        logging.error(f"Could not read current MAC for {interface}")
        return False
    print(f"[+] Current MAC: {current_mac}")
    logging.info(f"Current MAC: {current_mac}")
    
    if change_mac(interface, new_mac):
        new_current = get_mac_address(interface)
        if new_current == new_mac:
            print(f"[+] MAC successfully changed to {new_current}")
            logging.info(f"MAC successfully changed to {new_current}")
            return True
        else:
            print(f"[-] MAC change unsuccessful. Current MAC: {new_current}")
            logging.error(f"MAC change unsuccessful. Current: {new_current}")
            return False
    return False
