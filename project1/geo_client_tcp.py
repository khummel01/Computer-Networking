'''
GEO TCP Client
'''
#!/usr/bin/env python3

import socket

HOST = 'localhost'
PORT = 4300


def client(s):
    '''Main client loop'''
    # TODO: Implement client-side tasks
    country = input()
    while country != "BYE":
        s.sendall(country.encode())
        data = s.recv(1024)        
        print(data.decode())
        country = input()
    s.close()
    

def main():
    '''Main function'''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        data = s.recv(1024)
        print(data.decode())
        client(s)

if __name__ == "__main__":
    main()
