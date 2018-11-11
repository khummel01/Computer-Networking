"""Python Web server implementation"""
import socket
from datetime import datetime
import sys
import os

ADDRESS = "127.0.0.2"  # Local client is going to be 127.0.0.1
PORT = 4300  # Open http://127.0.0.2:4300 in a browser
LOGFILE = "webserver.log"


def server():
    '''Main server loop'''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ADDRESS, PORT))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            while True:
                data = conn.recv(1024).decode().split()
                time_of_request = datetime.now()
                print(data)

                if not data:
                    print("Disconnected: ", addr[0])
                    break

                with open(LOGFILE, 'a') as logFile:
                    logFile.write(str(time_of_request) + " | " + data[1] + " | " + addr[0] + " | " +
                                  data[12] + " " + data[13] + " " + data[14]+ " " + data[15] +
                                  " " + data[16] + " " + data[17] + " " + data[18] + " " +
                                  " " + data[19] + " " + data[20] + " " + data[21] + "\n")

                print("TYPE: ", data[0])
                if data[0] == "GET":
                    try:
                        file_to_send = open(data[1][1:], "rb")
                        response = file_to_send.read()
                        file_size = os.path.getsize(data[1][1:])
                        date = datetime.now().strftime("%c")
                        file_to_send.close()

                        header = 'HTTP/1.1 200 OK\nContent-Length: {}\nContent-Type: plain text; charset=utf-8\nDate: {}\n' \
                                 'Last-Modified: Wed Aug 29 11:00:00 2018\nServer: CS430-KATIE'.format(file_size, date).encode()

                    except Exception as e:
                        header = 'HTTP/1.1 404 Not Found\n'.encode()
                        response = 'ERROR: 404 file not found'.encode()
                else:
                    header = 'HTTP/1.1 405 Method Not Allowed\n'.encode()
                    response = 'ERROR: 405 method not allowed'.encode()

                print("HEADER: ", header)
                print("RESPONSE: ", response)
                conn.send(header)
                conn.send(b'\r\n\r\n')
                conn.send(response)
                print("----------------------END-------------------------")

def main():
    """Main loop"""
    server()


if __name__ == "__main__":
    main()
