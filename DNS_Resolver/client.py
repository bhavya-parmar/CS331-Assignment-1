import socket
from scapy.all import rdpcap, DNS
from datetime import datetime

rdpcap_file = '8.pcap'
print(f"Reading packets from {rdpcap_file}...")
packets = rdpcap(rdpcap_file)
print(packets)

# UDP server details
SERVER_IP = '127.0.0.1'
SERVER_PORT = 53

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
log = "Header, Query, Resolved IP\n"
seq_id = 0
for packet in packets:
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 and packet['UDP'].dport == 53:  # DNS query
        # print packet number
        print(f"Packet {packets.index(packet)}:")
        print(packet.summary())

        # Use current system time for header
        now = datetime.now()
        header = now.strftime('%H%M%S') + f"{seq_id:02d}"
        header_bytes = header.encode('ascii')  # 8 bytes

        # get raw DNS packet bytes
        dns_bytes = bytes(packet[DNS])
        # combine header and DNS bytes
        data = header_bytes + dns_bytes

        sock.sendto(data, (SERVER_IP, SERVER_PORT))
        response, server_addr = sock.recvfrom(1024)  # 1024 is buffer size
        log += f"{header}, {packet[DNS].qd.qname.decode('utf-8')}, {response.decode('utf-8')}\n"
        seq_id += 1

print(f"Total DNS queries sent: {seq_id}")
with open('afternoon_p8.txt', 'w') as f:
    f.write(log)

