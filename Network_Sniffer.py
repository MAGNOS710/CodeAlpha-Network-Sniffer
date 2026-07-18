from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, IPv6, Raw
from datetime import datetime
from time import sleep

packet_counter = 0

def packet_callback(packet): 
    global packet_counter 
    packet_counter += 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sleep(1)
    print("=" * 70)
    print(f"Packet #{packet_counter}")
    print(f"Time    : {timestamp}")
    print(f"Packet Size : {len(packet)} bytes")
    
    is_ip_packet = False

    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"IP Version: {ip_layer.version}")
        print(f"TTL: {ip_layer.ttl}")
        is_ip_packet = True
        
    elif IPv6 in packet:
        ipv6_layer = packet[IPv6]
        print(f"Source IP: {ipv6_layer.src}")
        print(f"Destination IP: {ipv6_layer.dst}")
        print(f"IP Version: 6")
        is_ip_packet = True

    elif ARP in packet:
        arp_layer = packet[ARP]
        print(f"Protocol: ARP")
        print(f"Source MAC: {arp_layer.hwsrc} -> IP: {arp_layer.psrc}")
        print(f"Dest MAC: {arp_layer.hwdst} -> IP: {arp_layer.pdst}")
        print("=" * 70)
        return 
    
    else:
        print("Protocol: Non-IP/Non-ARP Traffic")
        print("=" * 70)
        return 

    if is_ip_packet:
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP")
            print(f"Source Port : {tcp_layer.sport}")
            print(f"Destination Port : {tcp_layer.dport}")
            print(f"Flags : {tcp_layer.flags}")

        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol : UDP")
            print(f"Source Port : {udp_layer.sport}")
            print(f"Destination Port : {udp_layer.dport}")

        elif ICMP in packet:
            icmp_layer = packet[ICMP]
            print(f"Protocol : ICMP")
            print(f"Type : {icmp_layer.type}")
            print(f"Code : {icmp_layer.code}")
            
        else:
            print("Protocol : Other IP Protocol")
        
        if Raw in packet:
            payload = packet[Raw].load[:300]
            print("\n Payload : ")
            try:
                print(payload.decode(errors="ignore"))
            except Exception:
                print(payload)
            
    print("=" * 70)

def start_sniffer():
    print("[*] Starting Packet Sniffer...")
    print("[*] Press Ctrl + C to stop.\n")

    try:
        sniff(filter="ip or ip6 or arp", prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopping Packet Sniffer...")
        print(f"[*] Total Packets Captured: {packet_counter}")
        print("[*] Exiting...")
        
if __name__ == "__main__":
    start_sniffer()