"""Python Web server implementation"""
import socket
from datetime import datetime
import sys
import os

ADDRESS = "127.0.0.2"  # Local client is going to be 127.0.0.1
PORT = 4300  # Open http://127.0.0.2:4300 in a browser
LOGFILE = "webserver.log"

#len of data == 36 is good

def update_log(data, addr):
    time_of_request = datetime.now()

    with open(LOGFILE, 'a') as logFile:
        logFile.write(str(time_of_request) + " | " + data[1] + " | " + addr[0] + " | " +
                      data[12] + " " + data[13] + " " + data[14] + " " + data[15] +
                      " " + data[16] + " " + data[17] + " " + data[18] + " " +
                      " " + data[19] + " " + data[20] + " " + data[21] + "\n")

def get_header(response_code, file_size=0):
    date = datetime.now().strftime("%c")

    if response_code == 200:
        return 'HTTP/1.1 200 OK\nContent-Length: {}\nContent-Type: plain text; charset=utf-8\nDate: {}\n' \
                'Last-Modified: Wed Aug 29 11:00:00 2018\nServer: CS430-KATIE'.format(file_size, date)
    elif response_code == 404:
        return 'HTTP/1.1 404 Not Found\nDate: {}\nServer: CS430-KATIE'.format(date)
    return 'HTTP/1.1 405 Method Not Allowed\nDate: {}\nServer: CS430-KATIE'.format(date)

def server():
    '''Main server loop'''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ADDRESS, PORT))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            while True:
                print("AT THE TOP")
                data = conn.recv(1024).decode().split()
                print("DATA:")
                print(data)
                request_method = data[0]
                print("Request Method: ", request_method)

                if request_method == "GET":
                    update_log(data, addr)
                    try:
                        file_name = data[1][1:]
                        file_to_send = open(file_name, "rb")
                        response = file_to_send.read()
                        file_size = os.path.getsize(file_name)
                        file_to_send.close()
                        header = get_header(200, file_size).encode()

                        conn.send(header)
                        conn.send(b'\r\n\r\n')
                        conn.send(response)
                        print("----------------------END-------------------------")

                    except Exception as e:
                        header = get_header(404).encode()
                        response = 'ERROR: 404 file not found'.encode()
                        conn.send(header)
                        conn.send(b'\r\n\r\n')
                        conn.send(response)

                else:
                    conn.send("POST REQUEST NOT ALLOWED\n".encode())
                    conn.close()
                    # s.close()



def main():
    """Main loop"""
    server()


if __name__ == "__main__": main()
