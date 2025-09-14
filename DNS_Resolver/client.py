import socket
import struct
from datetime import datetime

def is_dns_packet(packet):
    # ethernet header is 14 bytes
    eth_header = packet[:14]
    eth_type = struct.unpack('!H', eth_header[12:14])[0]
    if eth_type != 0x0800:  # Not IPv4
        return (False, None)

    # IP header (minimum 20 bytes, but IHL can make it longer)
    ip_header = packet[14:34]
    version_ihl = ip_header[0]
    ihl = (version_ihl & 0x0F) * 4
    protocol = ip_header[9]
    if protocol != 17:  # Not UDP
        return (False, None)

    # UDP header (8 bytes)
    udp_start = 14 + ihl
    udp_header = packet[udp_start:udp_start+8]
    src_port, dst_port = struct.unpack('!HH', udp_header[:4])
    # check if either port is 53 (DNS)
    if src_port == 53 or dst_port == 53:
        return (True, packet[udp_start+8:])
    return (False, None)


# generator to read pcap file and yield DNS packets and their payloads
def read_pcap_and_find_dns(pcap_file):
    with open(pcap_file, 'rb') as f:
        # Skip global header (24 bytes)
        f.read(24)
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            incl_len = struct.unpack('I', pkt_hdr[8:12])[0]
            packet = f.read(incl_len)
            if len(packet) < incl_len:
                break
            is_dns, dns_payload = is_dns_packet(packet)
            if is_dns:
                yield (packet, dns_payload)


save_path = 'night_p8.txt'
pcap_file = '8.pcap'
# UDP server details
SERVER_IP = '127.0.0.1'
SERVER_PORT = 53

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
log = "Header, Query, Resolved IP\n"
seq_id = 0

print(f"Reading packets from {pcap_file}...")

for dns_packet, dns_payload in read_pcap_and_find_dns(pcap_file):
    #     # Use current system time for header
        now = datetime.now()
        header = now.strftime('%H%M%S') + f"{seq_id:02d}"
        header_bytes = header.encode('ascii')  # 8 bytes

        # get raw DNS packet bytes
        # print(dns_payload)
        qname = b''
        idx = 12  # DNS header is 12 bytes
        while True:
            length = dns_payload[idx]
            if length == 0:
                break
            qname += dns_payload[idx+1:idx+1+length] + b'.'
            idx += length + 1
        qname = qname.decode('utf-8')
        print(f"Sending DNS Query for Name: {qname}")
        # combine header and DNS bytes
        data = header_bytes + dns_payload

        sock.sendto(data, (SERVER_IP, SERVER_PORT))
        response, server_addr = sock.recvfrom(1024)  # 1024 is buffer size
        log += f"{header}, {qname}, {response.decode('utf-8')}\n"
        seq_id += 1

print(f"Total DNS queries sent: {seq_id}")
# print(log)
with open(save_path, 'w') as f:
    f.write(log)
print(f"Log saved to {save_path}")

