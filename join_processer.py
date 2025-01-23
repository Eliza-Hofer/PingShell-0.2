import socket
def append_to_register(address):
        with open('address_register.txt','a') as file:
                file.write(address + '\n')
def listen_for_join():
        server_ip = '0.0.0.0'
        server_port = 42069
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                sock.bind((server_ip, server_port))
                while True:
                        data, addr = sock.recvfrom(1024)
                        address = addr[0]
                        append_to_register(address)
listen_for_join()

