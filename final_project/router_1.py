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
ROUTING_TABLE = {} # {'destination':[cost, 'next_hop']}
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
            address = address + msg[index]
            if i < 3:
                address = address + "."
            index += 1
        # Extract cost
        cost = msg[index]
        index += 1

        # Add neighbors to NEIGHBORS
        NEIGHBORS.add(address)

        # Check if the table needs to be updated
        if address in ROUTING_TABLE and ROUTING_TABLE[address][0] > cost+ROUTING_TABLE[neigh_addr][0]:
            ROUTING_TABLE[address] = [cost, neigh_addr]
            isUpdated = True
        else:
            ROUTING_TABLE[address] = [cost, neigh_addr]
            isUpdated = True

    return isUpdated

def send_update(node):
    """Send update"""
    update_msg = format_update()
    # todo: pass in socket?
    socket.sendto(update_msg, (node, PORT))


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
    for ch in msg_txt:
        hello_msg.append(ord(ch))

    return hello_msg

# deliver_msg(msg)
def parse_hello(msg):
    """Send the message to an appropriate next hop"""
    dst_addr = ""
    for i in range(5,9):
        dst_addr = dst_addr + str(msg[i])
        if i < 8:
            dst_addr = dst_addr + "."
    next_hop = ROUTING_TABLE[dst_addr]
    #todo: send to next hop

# todo: check if you are the dest, if not, send to the next ho
def deliver_msg(msg):



def send_hello(msg_txt, src_node, dst_node):
    """Send a message"""
    format_hello_msg = format_hello(msg_txt, src_node, dst_node)
    #todo: finish


def print_status():
    """Print status"""
    print("{:>10} {:>10} {:>10}".format("HOST", "COST", "VIA"))
    for host in ROUTING_TABLE:
        print("{:>12} {:>7} {:>14}".format(host, ROUTING_TABLE[host][1], ROUTING_TABLE[host][0]))


def main(args: list):
    """Router main loop"""
    # NOTE: this is only for testing! The filename will be passed as a command line argument for final
    read_file('network_1_config.txt')

    # Print initial greeting message
    print(f"{time.strftime('%H:%M:%S')} | Router {THIS_NODE} here")
    print(f"{time.strftime('%H:%M:%S')} | Binding to {THIS_NODE}:{PORT}")
    print(f"{time.strftime('%H:%M:%S')} | Listening on {THIS_NODE}:{PORT}")

    # Print initial status
    print_status()

    # Start listening on UDP port 4300
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setblocking(0)
    server.bind((THIS_NODE, PORT))
    server.listen()
    inputs = [server]
    outputs = []
    message_queues = {}

    # todo: send initial hello message
    for neighbor in ROUTING_TABLE:
        send_hello(random.choice(MESSAGES), THIS_NODE, neighbor)

    # todo: once every minute or show, send another update, hello
        # should be able to send hello to everyone in your known network
    # todo: first decide where you want to send to, look up in distance vector, then create socket to that neighbor (create packet)

    while inputs:
        readable, writable, exceptional = select.select(
            inputs, outputs, inputs)

        for s in readable:
            if s is server:
                connection, client_address = s.accept()
                connection.setblocking(0) # makes the socket nonblocking
                # Add connection to listener list
                inputs.append(connection)
                # Add connection to message_queues
                message_queues[connection] = [] # Queue.Queue()
            else:
                data = s.recv(1024)
                if data:
                    print("MESSAGE_QUEUES: ", message_queues)
                    print("DATA:")
                    print(data)
                    message_queues[s].append(data)
                    # Add IP address to neighbor list #todo: may not be necessary
                    if client_address not in ROUTING_TABLE:
                        ROUTING_TABLE[client_address] = []
                    if s not in outputs:
                        outputs.append(s)
                else:
                    if s in outputs:
                        outputs.remove(s)
                    inputs.remove(s)
                    s.close()
                    del message_queues[s]
        # NOT NEEDED, NO QUEUE OF OUTGOING MESSAGES, this is already handled by the functions above
        # for s in writable:
        #     if len(message_queues[s]) == 0:
        #         outputs.remove(s)
        #     else:
        #         next_msg = message_queues[s].pop(0)
        #         s.send(next_msg)

        for s in exceptional:
            inputs.remove(s)
            if s in outputs:
                outputs.remove(s)
            s.close()
            del message_queues[s]


if __name__ == "__main__":
    main(sys.argv)
