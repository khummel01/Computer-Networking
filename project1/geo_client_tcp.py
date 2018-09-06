'''
GEO TCP Client
'''
#!/usr/bin/env python3

from socket import socket, AF_INET, SOCK_STREAM

HOST = 'localhost'
PORT = 4300


def client():
    '''Main client loop'''
    # TODO: Implement client-side tasks
    pass

def main():
    '''Main function'''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT)) 
        s.listen(1)        
        client()


if __name__ == "__main__":
    main()
