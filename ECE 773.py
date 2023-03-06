import socket
import threading
import logging

# specify the interface name and buffer size
interface = 'eth0'
buffer_size = 4096

# set up logging
logging.basicConfig(level=logging.INFO)

class InputThread(threading.Thread):
    def __init__(self, sock):
        threading.Thread.__init__(self)
        self.sock = sock

    def run(self):
        # loop indefinitely to receive data from the network interface
        while True:
            try:
                # receive the data and extract the raw bytes
                data, address = self.sock.recvfrom(buffer_size)
                raw_bytes = data

                # do something with the raw bytes...
                logging.info('Received {} bytes from {}'.format(len(raw_bytes), address))
                logging.debug('Raw bytes: {}'.format(raw_bytes))
            except socket.error as e:
                logging.error('Error receiving data: {}'.format(e))

# create a socket object with AF_PACKET family and SOCK_RAW type
try:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error as e:
    logging.error('Error creating socket: {}'.format(e))
    exit()

# bind the socket to the specified interface
try:
    sock.bind((interface, 0))
except socket.error as e:
    logging.error('Error binding to interface {}: {}'.format(interface, e))
    exit()

# start the input thread to receive data from the network interface
input_thread = InputThread(sock)
input_thread.daemon = True
input_thread.start()

# loop indefinitely to receive data from the network interface
while True:
    # receive the data and extract the raw bytes
    data, address = sock.recvfrom(buffer_size)
    raw_bytes = data

    # do something with the raw bytes...
    print(raw_bytes)
