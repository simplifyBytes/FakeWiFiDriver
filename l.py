import socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(('wlan0', 0))
s.send(b'\xff'*60)  # Send a dummy Ethernet frame
s.close()
