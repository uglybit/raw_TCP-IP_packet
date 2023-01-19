import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

packet = input()
destination_ip = input()

print(packet)
print(bytes.fromhex(packet))
print(destination_ip)

s.sendto(bytes.fromhex(packet), (destination_ip, 0))


