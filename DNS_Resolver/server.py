import socket

SERVER_IP = '127.0.0.1'
# DNS server
SERVER_PORT = 53
BUFFER_SIZE = 4096

IPs =  [
"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
"192.168.1.6", "192.168.1.7", "192.168.1.8", "192.168.1.9", "192.168.1.10", 
"192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14", "192.168.1.15"
]

rules = {
  "timestamp_rules": {
    "time_based_routing": {
      "morning": {
        "time_range": "04:00-11:59",
        "hash_mod": 5,
        "ip_pool_start": 0,
        "description": "Morning traffic routed to first 5 IPs"
      },
      "afternoon": {
        "time_range": "12:00-19:59", 
        "hash_mod": 5,
        "ip_pool_start": 5,
        "description": "Afternoon traffic routed to middle 5 IPs"
      },
      "night": {
        "time_range": "20:00-03:59",
        "hash_mod": 5,
        "ip_pool_start": 10,
        "description": "Night traffic routed to last 5 IPs"
      }
    }
  }
}

def resolve_dns_query(header):
    hour = int(header[0:2])
    ssid = int(header[6:8])
    print(f"Resolving DNS query with hour: {hour}, ssid: {ssid}")

    if hour < 4 or hour >= 20:
      slot = 'night'
    elif hour < 12:
      slot = 'morning'
    else:
      slot = 'afternoon'
    # applying the rules to determine resolved IP
    rule = rules['timestamp_rules']['time_based_routing'][slot]
    ip_index = (ssid % rule['hash_mod']) + rule['ip_pool_start']
    resolved_ip = IPs[ip_index]
    return resolved_ip

# create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# listen on DNS port
sock.bind((SERVER_IP, SERVER_PORT))
print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

while True:
  data, addr = sock.recvfrom(BUFFER_SIZE)
  if len(data) < 8:
    print(f"Received packet too short from {addr}")
    continue
  # extract header and resolve IP based on the rules given
  header = data[:8].decode('ascii', errors='replace')
  resolved_ip = resolve_dns_query(header)
  print(f"Sending resolved IP {resolved_ip} to {addr}")
  sock.sendto(resolved_ip.encode('utf-8'), addr)
  
