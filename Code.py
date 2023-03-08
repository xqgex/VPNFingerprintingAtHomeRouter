import socket
 
def read_raw_bytes(interface, filter_internal_communication=False, internal_as_source=False):
     # Create a new raw socket
     sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
 
     # Bind the socket to the network interface you want to read from
     sock.bind((interface, 0))
 
     # Read raw data from the socket
     while True:
         data, address = sock.recvfrom(65535)
 
         # Extract the source and destination IP addresses from the raw data
         ip_header = data[14:34]
         src_ip = socket.inet_ntoa(ip_header[12:16])
         dst_ip = socket.inet_ntoa(ip_header[16:20])
 
         # Apply filters if requested
         if filter_internal_communication:
             if is_private_ip(src_ip) and is_private_ip(dst_ip):
                 continue
         if internal_as_source:
             if is_private_ip(src_ip):
                 src_ip, dst_ip = dst_ip, src_ip
 
         # Return the source and destination IP addresses as integers
         return ip_to_int(src_ip), ip_to_int(dst_ip)
 
 def is_private_ip(ip_address):
     # Check if an IP address is in a private IP range
     ip_int = ip_to_int(ip_address)
     return (ip_int >> 24 == 10 or
             (ip_int >> 20 == (0xAC1 << 4) | 0x0) or
             (ip_int >> 16) == 0xC0A8)

def ip_to_int(ip_address):
    # Convert an IP address in dotted decimal notation to an integer
    return int.from_bytes(socket.inet_aton(ip_address), byteorder='big')

# Example usage
print(read_raw_bytes('eth0', filter_internal_communication=True, internal_as_source=True))
