"""Router implementation using UDP sockets"""
#!/usr/bin/env python3
# encoding: UTF-8


import os
import random
import select
import socket
import struct
import sys
import time

HOST_ID = os.path.splitext(__file__)[0].split("_")[-1]
THIS_NODE = f"127.0.0.{HOST_ID}"
PORT = 4300
NEIGHBORS = set()
ROUTING_TABLE = {} #{'destination':[cost, 'next_hop']}
TIMEOUT = 5
MESSAGES = [
    "Cosmic Cuttlefish",
    "Bionic Beaver",
    "Xenial Xerus",
    "Trusty Tahr",
    "Precise Pangolin"
]

def read_file(filename: str) -> None:
    """Read config file"""
    with open(filename, 'r') as infile:
        line = infile.readline().strip()
        # Find the appropriate router to start looking at
        while line != THIS_NODE:
            line = infile.readline().strip()

        # Update ROUTING_TABLE
        line = infile.readline()
        while line != "\n":
            neighbor = line.split()
            ROUTING_TABLE[neighbor[0]] = [neighbor[0], neighbor[1]]
            line = infile.readline()

    # Start listening on UDP port 4300
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((THIS_NODE, PORT))
        s.listen(1)

        # Print initial greeting message
        print(f"{time.strftime('%H:%M:%S')} | Router {THIS_NODE} here")
        print(f"{time.strftime('%H:%M:%S')} | Binding to {THIS_NODE}:{PORT}")
        print(f"{time.strftime('%H:%M:%S')} | Listening on {THIS_NODE}:{PORT}")

        conn, addr = s.accept()

        with conn:
            while True:
                data = conn.recv(1024)
                print(data)
                if not data:
                    break

def format_update():
    """Format update message"""
    update_msg = bytearray()
    update_msg.append(0)
    for node in ROUTING_TABLE:
        address = ROUTING_TABLE[node][0].split('.')
        cost = ROUTING_TABLE[node][1]
        for number in address:
            update_msg.append(int(number))
            update_msg.append(int(cost))
    return update_msg

def parse_update(msg, neigh_addr):
    """Update routing table"""
    isUpdated = False

    index = 1
    while index < len(bytearray):
        # Extract address
        address = ""
        for i in range(4):
            address = address + str(int.from_bytes(msg[index], byteorder="big"))
            if i < 3:
                address = address + "."
            index += 1
        # Extract cost
        pos_new_cost = str(int.from_bytes(msg[index], byteorder="big"))
        index += 1

        # Check if the table needs to be updated #todo: add cost of current
        if neigh_addr in ROUTING_TABLE and ROUTING_TABLE[neigh_addr][0] != pos_new_cost:
            ROUTING_TABLE[neigh_addr] = [pos_new_cost, address]
            isUpdated = True
        else:
            ROUTING_TABLE[neigh_addr] = [pos_new_cost, address]
            isUpdated = True

    return isUpdated

def send_update(node):
    """Send update"""
    raise NotImplementedError


def format_hello(msg_txt, src_node, dst_node):
    """Format hello message"""
    # Append type
    hello_msg = bytearray()
    hello_msg.append(1)

    # Append source address
    src_addr = src_node.split('.')
    for number in src_addr:
        hello_msg.append(number)

    # Append destination address
    dst_addr = dst_node.split('.')
    for number in dst_addr:
        hello_msg.append(number)

    # Append text
    #todo: is this right?
    for ch in msg_txt:
        hello_msg.append(ord(ch))

    return hello_msg

def parse_hello(msg):
    """Send the message to an appropriate next hop"""
    next_hop = msg[5:9]


def send_hello(msg_txt, src_node, dst_node):
    """Send a message"""
    format_hello_msg = format_hello(msg_txt, src_node, dst_node)


def print_status():
    """Print status"""
    print("{:>10} {:>10} {:>10}".format("HOST", "COST", "VIA"))
    for host in ROUTING_TABLE:
        print("{:>12} {:>7} {:>14}".format(host, ROUTING_TABLE[host][1], ROUTING_TABLE[host][0]))


def main(args: list):
    """Router main loop"""
    read_file('network_1_config.txt')


if __name__ == "__main__":
    main(sys.argv)
