import subprocess
import os
import logging
import threading
from colorama import Fore, Style, init
from pyfiglet import Figlet
from mac_changer import run_mac_changer
from network_scanner import run_network_scan
from arp_spoofer import run_arp_spoof
from packet_sniffer import run_packet_sniff
from port_scanner import run_port_scan

init(autoreset=True)

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename="logs/network_tool.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def check_root():
    if os.geteuid() != 0:
        print(Fore.RED + "[-] This tool requires root privileges. Run with sudo")
        logging.error("This tool requires root privileges. Run with sudo")
        exit(1)

def enable_ip_forwarding():
    try:
        subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=1"], stderr=subprocess.DEVNULL)
        print(Fore.GREEN + "[+] IP Forwarding enabled")
        logging.info("IP forwarding enabled")
        return True
    except Exception as e:
        print(Fore.RED + f"[-] Failed to enable IP forwarding: {e}")
        logging.error(f"Failed to enable IP forwarding: {e}")
        return False

def disable_ip_forwarding():
    try:
        subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=0"], stderr=subprocess.DEVNULL)
        print(Fore.GREEN + "[+] IP Forwarding disabled")
        logging.info("IP forwarding disabled")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to disable IP forwarding: {e}")
        logging.error(f"Failed to disable IP forwarding: {e}")

def run_combined_arp_sniff(target_ip, spoof_ip, interface, duration, http_only):
    stop_event = threading.Event()
    arp_thread = threading.Thread(target=run_arp_spoof, args=(target_ip, spoof_ip, interface, stop_event))
    sniff_thread = threading.Thread(target=run_packet_sniff, args=(interface, target_ip, duration, http_only, stop_event))

    print(Fore.BLUE + Style.BRIGHT + "\n=== ARP Spoofer + HTTP Sniffer ===" + Style.RESET_ALL)
    logging.info("Starting ARP Spoofer + HTTP Sniffer")
    enable_ip_forwarding()
    
    try:
        arp_thread.start()
        sniff_thread.start()
        sniff_thread.join()
        stop_event.set()
        arp_thread.join()
    except KeyboardInterrupt:
        print(Fore.RED + "[!] Detected CTRL+C. Stopping ARP spoofing and sniffing...")
        logging.info("Detected CTRL+C. Stopping ARP spoofing and sniffing")
        stop_event.set()
        arp_thread.join()
        sniff_thread.join()
    finally:
        disable_ip_forwarding()

def display_title():
    f = Figlet(font="slant")
    print(Fore.CYAN + Style.BRIGHT + f.renderText("ADH_CAPRI"))
    print(Fore.YELLOW + "Welcome to ADH_CAPRI - Your Network Security Testing Suite")
    print(Fore.YELLOW + "=" * 60 + Style.RESET_ALL)
    logging.info("Displayed ADH_CAPRI title")

def display_menu():
    print(Fore.BLUE + Style.BRIGHT + "\nAvailable Tools:")
    print(Fore.BLUE + "1. MAC Changer")
    print(Fore.BLUE + "2. Network Scanner")
    print(Fore.BLUE + "3. ARP Spoofer + HTTP Sniffer")
    print(Fore.BLUE + "4. Port Scanner")
    print(Fore.BLUE + "5. Full Attack Mode")
    print(Fore.BLUE + "0. Exit")
    print(Style.RESET_ALL)
    logging.info("Displayed menu: 1. MAC Changer, 2. Network Scanner, 3. ARP Spoofer + HTTP Sniffer, 4. Port Scanner, 5. Full Attack, 0. Exit")

def get_user_choice():
    while True:
        try:
            choice = input(Fore.GREEN + "\nEnter your choice (0-5): " + Style.RESET_ALL)
            if choice in ['0', '1', '2', '3', '4', '5']:
                logging.info(f"User selected choice: {choice}")
                return choice
            print(Fore.RED + "[-] Invalid choice. Please enter a number between 0 and 5")
            logging.error("Invalid choice entered")
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Exiting...")
            logging.info("User exited with Ctrl+C")
            exit(0)

def get_common_inputs():
    interface = input(Fore.GREEN + "Enter network interface (e.g., eth0, wlan0): " + Style.RESET_ALL).strip()
    logging.info(f"User entered interface: {interface}")
    return interface

def main():
    check_root()
    display_title()

    while True:
        display_menu()
        choice = get_user_choice()

        if choice == '0':
            print(Fore.YELLOW + "[+] Exiting ADH_CAPRI. Goodbye!")
            logging.info("Exiting ADH_CAPRI")
            break

        interface = None
        target = None
        spoof = None
        mac = None
        ports = "1-500"
        duration = 60
        http_only = True

        if choice in ['1', '3', '5']:
            interface = get_common_inputs()
        if choice in ['2', '3', '4', '5']:
            target = input(Fore.GREEN + "Enter target IP or range (e.g., 192.168.1.0/24): " + Style.RESET_ALL).strip()
            logging.info(f"User entered target: {target}")
        if choice in ['3', '5']:
            spoof = input(Fore.GREEN + "Enter spoofed IP (e.g., gateway IP): " + Style.RESET_ALL).strip()
            logging.info(f"User entered spoof IP: {spoof}")
        if choice == '1' or (choice == '5' and input(Fore.GREEN + "Change MAC address? (y/n): " + Style.RESET_ALL).lower() == 'y'):
            mac = input(Fore.GREEN + "Enter new MAC address (e.g., 00:11:22:33:44:55): " + Style.RESET_ALL).strip()
            logging.info(f"User entered MAC: {mac}")
        if choice in ['3', '5']:
            http_only = input(Fore.GREEN + "Sniff HTTP only? (y/n, default y): " + Style.RESET_ALL).lower() != 'n'
            logging.info(f"User selected HTTP only: {http_only}")
            duration = int(input(Fore.GREEN + "Enter sniff duration (seconds, default 60): " + Style.RESET_ALL) or 60)
            logging.info(f"User entered sniff duration: {duration}")
        if choice in ['4', '5']:
            ports = input(Fore.GREEN + "Enter port range (e.g., 1-500, default 1-500): " + Style.RESET_ALL).strip() or "1-500"
            logging.info(f"User entered port range: {ports}")

        logging.info(f"Selected tool: {choice}, Inputs: interface={interface}, target={target}, spoof={spoof}, mac={mac}, ports={ports}, duration={duration}, http_only={http_only}")

        if choice == '1':
            print(Fore.BLUE + Style.BRIGHT + "\n=== MAC Changer ===" + Style.RESET_ALL)
            logging.info("Starting MAC Changer")
            if interface and mac:
                run_mac_changer(interface, mac)
            else:
                print(Fore.RED + "[-] Interface and MAC address are required")
                logging.error("Interface and MAC address are required")
        
        elif choice == '2':
            print(Fore.BLUE + Style.BRIGHT + "\n=== Network Scanner ===" + Style.RESET_ALL)
            logging.info("Starting Network Scanner")
            if target:
                run_network_scan(target)
            else:
                print(Fore.RED + "[-] Target IP/range is required")
                logging.error("Target IP/range is required")
        
        elif choice == '3':
            if interface and target and spoof:
                run_combined_arp_sniff(target, spoof, interface, duration, http_only)
            else:
                print(Fore.RED + "[-] Interface, target, and spoof IP are required")
                logging.error("Interface, target, and spoof IP are required")
        
        elif choice == '4':
            print(Fore.GREEN + Style.BRIGHT + "\n=== Port Scanner ===" + Style.RESET_ALL)
            logging.info("Starting Port Scanner")
            if target:
                run_port_scan(target, ports)
            else:
                print(Fore.RED + "[-] Target IP is required")
                logging.error("Target IP is required")
        
        elif choice == '5':
            print(Fore.YELLOW + Style.BRIGHT + "\n=== Full Attack Mode ===" + Style.RESET_ALL)
            logging.info("Starting Full Attack Mode")
            if not all([interface, target, spoof, ports]):
                print(Fore.RED + "[-] Interface, target, spoof IP, and ports are required")
                logging.error("Interface, target, spoof IP, and ports are required")
                continue
            if mac:
                print(Fore.BLUE + Style.BRIGHT + "\n[MAC Changer]" + Style.RESET_ALL)
                logging.info("Starting MAC Changer in Full Attack")
                run_mac_changer(interface, mac)
            print(Fore.BLUE + Style.BRIGHT + "\n[Network Scanner]" + Style.RESET_ALL)
            logging.info("Starting Network Scanner in Full Attack")
            devices = run_network_scan(target)
            target_to_use = devices[0]["ip"] if devices else target
            print(Fore.RED + Style.BRIGHT + "\n[ARP Spoofer + HTTP Sniffer]" + Style.RESET_ALL)
            logging.info("Starting ARP Spoofer + HTTP Sniffer in Full Attack")
            run_combined_arp_sniff(target_to_use, spoof, interface, duration, http_only)
            print(Fore.GREEN + Style.BRIGHT + "\n[Port Scanner]" + Style.RESET_ALL)
            logging.info("Starting Port Scanner in Full Attack")
            run_port_scan(target_to_use, ports)

if __name__ == "__main__":
    main()
