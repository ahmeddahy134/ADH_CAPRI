import socket
from IPy import IP
import logging
from colorama import Fore, init

init(autoreset=True)
logging.basicConfig(filename="logs/network_tool.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class PortScan:
    banners = []
    open_ports = []

    def __init__(self, target, port_range):
        self.target = target
        self.start_port, self.end_port = map(int, port_range.split('-'))

    def check_ip(self):
        try:
            IP(self.target)
            return self.target
        except ValueError:
            try:
                return socket.gethostbyname(self.target)
            except Exception as e:
                print(Fore.RED + f"[-] Failed to resolve IP for {self.target}: {e}")
                logging.error(f"Failed to resolve IP for {self.target}: {e}")
                return None

    def scan_port(self, port):
        try:
            converted_ip = self.check_ip()
            if not converted_ip:
                return
            sock = socket.socket()
            sock.settimeout(0.5)
            result = sock.connect_ex((converted_ip, port))
            if result == 0:
                self.open_ports.append(port)
                try:
                    banner = sock.recv(1024).decode().strip('\n').strip('\r')
                    self.banners.append(banner)
                except:
                    self.banners.append(' ')
                print(Fore.GREEN + f"[+] Port {port} is open - Banner: {self.banners[-1]}")
                logging.info(f"Port {port} open - Banner: {self.banners[-1]}")
            sock.close()
        except Exception as e:
            print(Fore.RED + f"[-] Error scanning port {port}: {e}")
            logging.error(f"Error scanning port {port}: {e}")

    def scan(self):
        print(Fore.GREEN + f"[+] Scanning ports {self.start_port}-{self.end_port} on {self.target}...")
        logging.info(f"Starting port scan on {self.target} from port {self.start_port} to {self.end_port}")
        for port in range(self.start_port, self.end_port + 1):
            self.scan_port(port)
        if self.open_ports:
            print(Fore.GREEN + f"\n[+] Open ports summary: {self.open_ports}")
            print(Fore.GREEN + f"[+] Banners: {self.banners}")
            logging.info(f"Open ports summary: {self.open_ports}")
            logging.info(f"Banners: {self.banners}")
        else:
            print(Fore.RED + "[-] No open ports found")
            logging.info("No open ports found")

def run_port_scan(target_ip, port_range="1-500"):
    try:
        scanner = PortScan(target_ip, port_range)
        scanner.scan()
        return scanner.open_ports
    except ValueError as e:
        print(Fore.RED + f"[-] Invalid input: {e}")
        logging.error(f"Invalid input: {e}")
        return []
    except Exception as e:
        print(Fore.RED + f"[-] Scan failed: {e}")
        logging.error(f"Scan failed: {e}")
        return []
