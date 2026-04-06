from scapy.all import *
from datetime import datetime
import base64

# Helper function to create a timestamp
def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# List to store all crafted packets
packets = []

# 1. Student's packet
student_name = "maria"
student_id = "12345678"
student_payload = f"{student_name}-{student_id} {get_timestamp()}"
student_packet = IP(src="192.168.100.1", dst="192.168.1.1") / TCP(dport=54321) / Raw(load=student_payload)
packets.append(student_packet)

# 2. Port scan packets
services = {
    "HTTP": 80,
    "HTTPS": 443,
    "SSH": 22,
    "TELNET": 23,
    "FTP": 21,
    "DNS": 53,
    "RTSP": 554,
    "SQL": 1433,
    "RDP": 3389,
    "MQTT": 1883
}

for service, port in services.items():
    port_scan_payload = f"{student_name}-{student_id} {get_timestamp()}"
    packet = IP(src="192.168.100.2", dst="192.168.1.2") / TCP(dport=port) / Raw(load=port_scan_payload)
    packets.append(packet)

# 3. Base64 malicious packets
malicious_payload = base64.b64encode(student_id.encode()).decode()
for _ in range(5):
    malicious_packet = IP(src="192.168.100.3", dst="192.168.1.3") / TCP(dport=8080) / Raw(load=malicious_payload)
    packets.append(malicious_packet)

# 4. DNS suspicious domain packet
dns_payload = DNS(rd=1, qd=DNSQR(qname="malicious.example.com"))
dns_packet = IP(src="192.168.100.4", dst="192.168.1.1") / UDP(dport=53) / dns_payload
packets.append(dns_packet)

# 5. Ping test packet
ping_payload = "PingTest-2024"
ping_packet = IP(src="192.168.100.5", dst="192.168.1.4") / ICMP() / Raw(load=ping_payload)
packets.append(ping_packet)

# Save packets to a PCAP file
wrpcap("custom_traffic.pcap", packets)
print("Custom packets saved to custom_traffic.pcap")
