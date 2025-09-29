import scapy.all as scapy
import logging

logging.basicConfig(filename="logs/network_tool.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def scan(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        final_request = broadcast/arp_request
        answered_list = scapy.srp(final_request, timeout=2, verbose=False)[0]
        client_list = [{"ip": i[1].psrc, "mac": i[1].hwsrc} for i in answered_list]
        return client_list
    except Exception as e:
        print(f"[-] Network scan failed: {e}")
        logging.error(f"Network scan failed for {ip}: {e}")
        return []

def print_output(client_list):
    print("IP Address\t\t\tMAC Address")
    logging.info("Network scan results: IP Address\t\t\tMAC Address")
    print("-" * 38)
    logging.info("-" * 38)
    for client in client_list:
        print(f"{client['ip']}\t\t\t{client['mac']}")
        logging.info(f"{client['ip']}\t\t\t{client['mac']}")

def run_network_scan(target_ip):
    print(f"[+] Scanning network: {target_ip}")
    logging.info(f"Starting network scan on {target_ip}")
    scan_result = scan(target_ip)
    if scan_result:
        print_output(scan_result)
    else:
        print("[-] No devices found")
        logging.info("No devices found")
    return scan_result
