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
ROUTING_TABLE = {}
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
            ROUTING_TABLE[neighbor[0]] = [neighbor[0],neighbor[1]]
            line = infile.readline()

    # # Start listening on UDP port 4300
    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #     s.bind((THIS_NODE, PORT))
    #     s.listen(1)
    #
    #     # Print initial greating message
    #     print(f"{time.strftime('%H:%M:%S')} | Router {THIS_NODE} here")
    #     print(f"{time.strftime('%H:%M:%S')} | Binding to {THIS_NODE}:{PORT}")
    #     print(f"{time.strftime('%H:%M:%S')} | Listening on {THIS_NODE}:{PORT}")
    #
    #     # Print router's neighborhood
    #     print("{:>10} {:>10} {:>10}".format("HOST", "COST", "VIA"), end="")
    #     conn, addr = s.accept()
    #
    #     with conn:
    #         while True:
    #             data = conn.recv(1024)
    #             if not data:
    #                 break
    # Print initial greating message
    print(f"{time.strftime('%H:%M:%S')} | Router {THIS_NODE} here")
    print(f"{time.strftime('%H:%M:%S')} | Binding to {THIS_NODE}:{PORT}")
    print(f"{time.strftime('%H:%M:%S')} | Listening on {THIS_NODE}:{PORT}")

    # Print router's neighborhood
    print("{:>10} {:>10} {:>10}".format("HOST", "COST", "VIA"))
    for host in ROUTING_TABLE:
        print("{:>12} {:>7} {:>14}".format(host, ROUTING_TABLE[host][1], ROUTING_TABLE[host][0]))


def format_update():
    """Format update message"""
    raise NotImplementedError


def parse_update(msg, neigh_addr):
    """Update routing table"""
    raise NotImplementedError


def send_update(node):
    """Send update"""
    raise NotImplementedError


def format_hello(msg_txt, src_node, dst_node):
    """Format hello message"""
    raise NotImplementedError


def parse_hello(msg):
    """Send the message to an appropriate next hop"""
    raise NotImplementedError


def send_hello(msg_txt, src_node, dst_node):
    """Send a message"""
    raise NotImplementedError


def print_status():
    """Print status"""
    raise NotImplementedError


def main(args: list):
    """Router main loop"""
    read_file('network_1_config.txt')


if __name__ == "__main__":
    main(sys.argv)
