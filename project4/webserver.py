"""Python Web server implementation"""
import socket
from datetime import datetime
import sys
import os

ADDRESS = "127.0.0.2"  # Local client is going to be 127.0.0.1
PORT = 4300  # Open http://127.0.0.2:4300 in a browser
LOGFILE = "webserver.log"


def update_log(data, data_dict):
    time_of_request = datetime.now()
    with open(LOGFILE, 'a') as logFile:
        logFile.write(str(time_of_request) + " | " + data_dict["File"] + " | " + data_dict["Address"] + " | " + data_dict["User-Agent"])

def get_header(response_code, file_size=0):
    date = datetime.now().strftime("%c")

    if response_code == 200:
        # can we hard code http/1.1?
        return 'HTTP/1.1 200 OK\nContent-Length: {}\nContent-Type: plain text; charset=utf-8\nDate: {}\n' \
                'Last-Modified: Wed Aug 29 11:00:00 2018\nServer: CS430-KATIE'.format(file_size, date)
    elif response_code == 404:
        return 'HTTP/1.1 404 Not Found\r\n\r\n'
    return 'HTTP/1.1 405 Method Not Allowed\r\n\r\n'

def server():
    '''Main server loop'''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ADDRESS, PORT))
        s.listen(1)
        while True:
            conn, addr = s.accept()
            data_dict = {}
            data = conn.recv(1024).decode()

            # Create dictionary of data
            data = data.split('\r\n')
            type_file_version = data[0].split()
            data_dict["Request Method"] = type_file_version[0]
            data_dict["File"] = type_file_version[1]
            data_dict["Version"] = type_file_version[2]
            data_dict["Address"] = addr[0]

            for i in range(2, len(data)):
                if len(data[i]) > 1:
                    data_snippet = data[i].split(":")
                    data_dict[data_snippet[0]] = data_snippet[1]

            if data_dict["Request Method"] == "GET":
                update_log(data, data_dict)
                try:
                    file_name = data_dict["File"][1:]
                    file_to_send = open(file_name, "rb")
                    response = file_to_send.read()
                    file_size = os.path.getsize(file_name)
                    file_to_send.close()
                    header = get_header(200, file_size).encode()

                    conn.send(header)
                    conn.send(b'\r\n\r\n')
                    conn.send(response)
                    conn.close()

                except Exception as e:
                    header = get_header(404).encode()
                    conn.send(header)
                    conn.close()
            else:
                # curl -i -X
                header = get_header(405).encode()
                # conn.send("POST REQUEST NOT ALLOWED\n".encode())
                conn.send(header)
                conn.close()


def main():
    """Main loop"""
    server()


if __name__ == "__main__": main()
