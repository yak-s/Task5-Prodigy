from scapy.all import sniff, IP, TCP, UDP, Raw

def analyze(packet):
    if IP in packet or TCP in packet or UDP in packet:
        ip_layer = packet[IP]
        protocolNumber = ip_layer.proto
        
        if protocolNumber == 6:
            protocolName = "TCP"
        elif protocolNumber== 17:
            protocolName = "UDP"

        payloadData = ""
        if Raw in packet:
            payloadData = packet[Raw].load
        else:
            payloadData="Payload not available"
    
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {protocolName}")
        print(f"Payload: {payloadData}")
        print("-" * 150)

def main():
    print("Packets captured:\n")
    sniff(prn=analyze, store=False, count=5)

if __name__ == "__main__":
    main()
