from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"\n[+] Packet captured:")
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")

        if TCP in packet:
            print("Protocol: TCP")
            payload = packet[TCP].payload
        elif UDP in packet:
            print("Protocol: UDP")
            payload = packet[UDP].payload
        else:
            payload = packet[IP].payload
        
        print(f"Payload:\n{payload}")

# Sniff packets on all available interfaces
sniff(prn=packet_callback, store=0)

