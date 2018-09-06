'''
GEO TCP Server
'''
#!/usr/bin/env python3

from socket import socket, AF_INET, SOCK_STREAM
import datetime

FILE_NAME = 'geo_world.txt'
HOST = 'localhost'
PORT = 4300


def read_file(filename: str) -> dict:
    '''Read world territories and their capitals from the provided file'''
    world = dict()    
    
    with open(FILE_NAME) as worldData:
        print("Reading in a file...")
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
        s.connect((HOST, PORT))
        s.listen(1)
        conn, addr = s.accept()


def main():
    '''Main function'''
    world = read_file(FILE_NAME)
    server(world)    


if __name__ == "__main__":
    main()
