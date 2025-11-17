from scapy.all import ARP, sniff
import time

arp_table = {}
last_status_time = 0

def detect_arp_spoof(packet):
    global last_status_time

    if packet.haslayer(ARP) and packet[ARP].op == 2:  
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in arp_table and arp_table[ip] != mac:
            print(f"⚠️ [ALERT] Possible ARP spoofing detected!")
            print(f"IP: {ip} is being spoofed. Original MAC: {arp_table[ip]}, New MAC: {mac}")
        else:
            arp_table[ip] = mac


    current_time = time.time()
    if current_time - last_status_time > 10:
        print("[✔] No ARP spoofing detected. Network looks safe.")
        last_status_time = current_time

def start_arp_spoof_detector():
    print("[*] Starting ARP spoof detection... Press Ctrl+C to stop.")
    sniff(store=False, prn=detect_arp_spoof)

if __name__ == "__main__":
    start_arp_spoof_detector()
