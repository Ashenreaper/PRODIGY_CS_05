from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet.sprintf("%IP.proto%")

        payload = b""
        if Raw in packet:
            payload = packet[Raw].load

        payload_hex = payload.hex() if payload else "No Payload"

        print(f"[{timestamp}] Packet:")
        print(f"  Source IP:      {src_ip}")
        print(f"  Destination IP: {dst_ip}")
        print(f"  Protocol:       {protocol}")

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"  TCP Ports:      {src_port} -> {dst_port}")
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"  UDP Ports:      {src_port} -> {dst_port}")
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(f"  ICMP Type:      {icmp_type}, Code: {icmp_code}")

        print(f"  Payload (Hex):  {payload_hex[:60]} {'...' if len(payload_hex) > 60 else ''}") # Display first 60 bytes
        print("-" * 30)

def main():
    """
    Main function to start the packet sniffer.
    """
    interface = input("Enter the network interface to sniff (e.g., eth0, wlan0): ")
    try:
        print(f"\n👂 Listening for packets on interface '{interface}'... (Press Ctrl+C to stop)\n")
        sniff(iface=interface, store=False, prn=packet_callback)
    except PermissionError:
        print(
            "\n⚠️ Permission denied. Please run this script with administrator/root privileges.\n"
            "   (e.g., using 'sudo python your_script_name.py' on Linux/macOS)\n"
        )
    except Exception as e:
        print(f"\nAn error occurred: {e}\n")

if __name__ == "__main__":
    from scapy.all import Raw  # Import Raw here to avoid issues if scapy isn't installed initially
    main()