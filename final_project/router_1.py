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
PORT = 4300 + int(HOST_ID)
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
        line = infile.readline().strip().split()
        while len(line) > 0:
            ROUTING_TABLE[line[0]] = [int(line[1]), line[0]]
            NEIGHBORS.add(line[0])
            line = infile.readline().strip().split()

def format_update():
    """Format update message"""
    update_msg = bytearray()
    update_msg.append(0)
    for node in ROUTING_TABLE:
        address = node.split('.')
        cost = ROUTING_TABLE[node][0]
        for number in address:
            update_msg.append(int(number))
        update_msg.append(int(cost))
    return update_msg

def parse_update(msg, neigh_addr):
    """Update routing table"""
    isUpdated = False

    index = 1
    while index < len(msg):
        # Extract address
        address = ""
        for i in range(4):
            address = address + str(msg[index])
            if i < 3:
                address = address + "."
            index += 1
        # Extract cost
        cost = msg[index]
        index += 1

        # Make sure the address is not THIS_NODE because we don't want it in ROUTING_TABLE
        if address != THIS_NODE:
            # Check if the table needs to be updated
            cost_to_addr = cost+ROUTING_TABLE[neigh_addr][0]
            if address in ROUTING_TABLE:
                if ROUTING_TABLE[address][0] > cost_to_addr:
                    ROUTING_TABLE[address] = [cost_to_addr, ROUTING_TABLE[neigh_addr][1]]
                    isUpdated = True
            else:
                ROUTING_TABLE[address] = [cost_to_addr, ROUTING_TABLE[neigh_addr][1]]
                isUpdated = True

    return isUpdated

def send_update(neigh_addr, socket):
    """Send update"""
    update_msg = format_update()
    socket.sendto(update_msg, (neigh_addr, 4300+int(neigh_addr[-1])))

def format_hello(msg, src_addr, dst_addr):
    """Format hello message"""
    # Append type
    hello_msg = bytearray()
    hello_msg.append(1)

    # Append source address
    src_addr_split = src_addr.split('.')
    for number in src_addr_split:
        hello_msg.append(int(number))

    # Append destination address
    dst_addr_split = dst_addr.split('.')
    for number in dst_addr_split:
        hello_msg.append(int(number))

    # Append text
    hello_msg.extend(msg.encode('latin-1'))

    return hello_msg

def parse_hello(msg, socket):
    """Parse hello message"""
    dst_addr = ""
    for i in range(5, 9):
        dst_addr = dst_addr + str(msg[i])
        if i < 8:
            dst_addr = dst_addr + "."

    # This node is not the destination, forward to next hop
    if dst_addr != THIS_NODE:
        forward_msg(msg, dst_addr, socket)

    # This node is the destination, print hello message
    else:
        src_addr = ""
        for i in range(1, 5):
            src_addr = src_addr + str(msg[i])
            if i < 4:
                src_addr = src_addr + "."
        print(f"{time.strftime('%H:%M:%S')} | Received {msg[9:].decode()} from {src_addr}")

def forward_msg(msg, dst_addr, socket):
    """Send the message to the appropriate next hop"""
    next_hop = ROUTING_TABLE[dst_addr][1]
    print(f"{time.strftime('%H:%M:%S')} | Sending {msg[9:].decode()} to {dst_addr} via {next_hop}")
    socket.sendto(msg, (next_hop, 4300+int(next_hop[-1])))

def send_hello(msg, socket):
    """Send a message"""
    dst_addr = ""
    for i in range(5, 9):
        dst_addr = dst_addr + str(msg[i])
        if i < 8:
            dst_addr = dst_addr + "."
    next_hop = ROUTING_TABLE[dst_addr][1]
    print(f"{time.strftime('%H:%M:%S')} | Sending {msg[9:].decode()} to {dst_addr} via {next_hop}")
    socket.sendto(msg, (next_hop, 4300+int(next_hop[-1])))

def print_status():
    """Print status"""
    print("{:>10} {:>10} {:>10}".format("HOST", "COST", "VIA"))
    for host in ROUTING_TABLE:
        print("{:>12} {:>7} {:>14}".format(host, ROUTING_TABLE[host][0], ROUTING_TABLE[host][1]))


def main(args: list):
    """Router main loop"""
    read_file(args[1])

    # Print initial greeting message
    print(f"{time.strftime('%H:%M:%S')} | Router {THIS_NODE} here")
    print(f"{time.strftime('%H:%M:%S')} | Binding to {THIS_NODE}:{PORT}")
    print(f"{time.strftime('%H:%M:%S')} | Listening on {THIS_NODE}:{PORT}")

    # Print initial status
    print_status()

    # Start listening on UDP port
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((THIS_NODE, PORT))
    read_from = [server]
    write_to = []
    exceptions = []
    message_queues = {}

    # Create socket to send messages to
    out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    out_sock.bind((THIS_NODE, 4300))

    # Wait to send initial update message until all routers have woken up
    time.sleep(5)

    # Initial update message
    for neighbor in NEIGHBORS:
        send_update(neighbor, server)

    # Start timer for hello messages
    start_time = time.time()

    while read_from:
        readable, writable, exceptional = select.select(
            read_from, write_to, exceptions)

        # List of sockets to read from
        for s in readable:
            msg, addr = s.recvfrom(4096)

            # This is an update message
            if msg[0] == 0:
                updated = parse_update(msg, addr[0])
                if updated:
                    # Print this router's new table
                    print(f"{time.strftime('%H:%M:%S')} | Table updated with information from {addr[0]}")
                    print_status()

                    # Let other routers know that about the update
                    if out_sock in message_queues:
                        message_queues[out_sock].append(format_update())
                    else:
                        message_queues[out_sock] = [format_update()]
                    write_to.append(out_sock)

            # This is a hello message
            else:
                parse_hello(msg, server)

        # List of sockets to write to
        for s in writable:
            if len(message_queues[s]) > 0:
                msg = message_queues[s].pop(0)
                if msg[0] == 0:
                    for neighbor in NEIGHBORS:
                        send_update(neighbor, server)
                else:
                    send_hello(msg, server)

        # Errors
        for s in exceptional:
            read_from.remove(s)
            if s in write_to:
                write_to.remove(s)
            s.close()
            del message_queues[s]

        # Send hello message every 15 seconds
        end_time = time.time()
        total_time = end_time - start_time
        if total_time > 15:
            if out_sock in message_queues:
                message_queues[out_sock].append(format_hello(random.choice(MESSAGES), THIS_NODE, random.choice(list(NEIGHBORS))))
            else:
                message_queues[out_sock].append(format_hello(random.choice(MESSAGES), THIS_NODE, random.choice(list(NEIGHBORS))))
            write_to.append(out_sock)

            start_time = time.time()


if __name__ == "__main__":
    main(sys.argv)
