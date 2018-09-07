'''
GEO TCP Server
'''
#!/usr/bin/env python3

import socket
import datetime

FILE_NAME = 'geo_world.txt'
HOST = 'localhost'
PORT = 4300


def read_file(filename: str) -> dict:
    '''Read world territories and their capitals from the provided file'''
    world = dict()    
    
    with open(FILE_NAME) as worldData:
        print("Reading a file...")
        starttime = datetime.datetime.now()
        for line in worldData:
            dataLst = line.split(" - ")
            world[dataLst[0].strip()] = dataLst[1].strip()
        endtime = datetime.datetime.now()
        deltaT = endtime - starttime
        deltaTParsed = str(deltaT)[7:]
        print("Read in " + str(deltaTParsed) + " sec")
        
    return world


def server(world: dict) -> None:
    '''Main server loop'''
    # TODO: Implement server-side tasks
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print("Listening on localhost:4300")
        conn, addr = s.accept()
        with conn:
            print("Connected: " + addr[0])
            conn.sendall("You are connected to the GEO101 server\n".encode())
            conn.sendall("Enter a country or BYE to quit".encode())
            while True:
                data = conn.recv(1024)
                if not data:
                    print("Disconnected: ", addr[0])
                    break
                
                country = data.decode()
                print("User query: ", country)
                if country in world.keys():
                    capital = world[country]
                    conn.sendall(("+" + capital + "\nEnter another country or BYE to quit").encode())
                else:
                    conn.sendall("-There is no such country\nEnter another country or BYE to quit".encode())

def main():
    '''Main function'''
    world = read_file(FILE_NAME)
    server(world)    


if __name__ == "__main__":
    main()
