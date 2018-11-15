"""Python Pinger"""
#!/usr/bin/env python3
# encoding: UTF-8

import binascii
import os
import select
import struct
import sys
import time
import socket
from statistics import mean, stdev

ECHO_REQUEST_TYPE = 8
ECHO_REPLY_TYPE = 0
ECHO_REQUEST_CODE = 0
ECHO_REPLY_CODE = 0
REGISTRARS = ["afrinic.net", "apnic.net", "arin.net", "lacnic.net", "ripe.net"]
# REGISTRARS = ["example.com"]


def print_raw_bytes(pkt: bytes) -> None:
    """Printing the packet bytes"""
    for i in range(len(pkt)):
        sys.stdout.write("{:02x} ".format(pkt[i]))
        if (i + 1) % 16 == 0:
            sys.stdout.write("\n")
        elif (i + 1) % 8 == 0:
            sys.stdout.write("  ")
    sys.stdout.write("\n")


def checksum(pkt: bytes) -> int:
    """Calculate checksum"""
    csum = 0
    count = 0
    count_to = (len(pkt) // 2) * 2

    while count < count_to:
        this_val = (pkt[count + 1]) * 256 + (pkt[count])
        csum = csum + this_val
        csum = csum & 0xFFFFFFFF
        count = count + 2

    if count_to < len(pkt):
        csum = csum + (pkt[len(pkt) - 1])
        csum = csum & 0xFFFFFFFF

    csum = (csum >> 16) + (csum & 0xFFFF)
    csum = csum + (csum >> 16)
    result = ~csum
    result = result & 0xFFFF
    result = result >> 8 | (result << 8 & 0xFF00)

    return result


def parse_reply(
    my_socket: socket.socket, req_id: int, timeout: int, addr_dst: str
) -> tuple:
    """Receive an Echo reply"""
    '''
    parse_reply: receives and parses an echo reply. Takes the following arguments: 
    socket, request id, timeout, and the destination address. Returns a tuple of the 
    destination address, packet size, roundtrip time, time to live, and sequence number. 
    You need to modify lines between labels TODO and DONE. This function should raise 
    an error if the response message type, code, or checksum are incorrect.
    '''
    time_left = timeout
    while True:
        started_select = time.time()
        what_ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = time.time() - started_select
        if what_ready[0] == []:  # Timeout
            raise TimeoutError("Request timed out after 1 sec")

        time_rcvd = time.time()
        pkt_rcvd, addr = my_socket.recvfrom(1024)
        if addr[0] != addr_dst:
            raise ValueError(f"Wrong sender: {addr[0]}")
        # TODO: Extract ICMP header from the IP packet and parse it
        # print_raw_bytes(pkt_rcvd)
        # DONE: End of ICMP parsing
        time_left = time_left - how_long_in_select
        if time_left <= 0:
            raise TimeoutError("Request timed out after 1 sec")


def format_request(req_id: int, seq_num: int) -> bytes:
    """Format an Echo request"""
    my_checksum = 0
    header = struct.pack(
        "bbHHh", ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE, my_checksum, req_id, seq_num
    )
    data = struct.pack("d", time.time())
    my_checksum = checksum(header + data)

    if sys.platform == "darwin":
        my_checksum = socket.htons(my_checksum) & 0xFFFF
    else:
        my_checksum = socket.htons(my_checksum)

    header = struct.pack(
        "bbHHh", ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE, my_checksum, req_id, seq_num
    )
    packet = header + data
    return packet


def send_request(addr_dst: str, seq_num: int, timeout: int = 1) -> tuple:
    """Send an Echo Request"""
    result = None
    proto = socket.getprotobyname("icmp")
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
    my_id = os.getpid() & 0xFFFF

    packet = format_request(my_id, seq_num)
    my_socket.sendto(packet, (addr_dst, 1))

    try:
        result = parse_reply(my_socket, my_id, timeout, addr_dst)
    except ValueError as ve:
        print(f"Packet error: {ve}")
    finally:
        my_socket.close()
    return result


def ping(host: str, pkts: int, timeout: int = 1) -> None:
    '''Main loop: displays host statistics '''
    # TODO: Implement the main loop

    with open('output', 'a') as outfile:
        rtt_arr = []
        num_pkts_received = 0
        for i in range(pkts):
            try:
                dest_addr, pkt_size, rtt, ttl, seq_num = send_request(host, pkts, timeout) # send_request() calls format_request(), then parse_reply() within itself
                if i == 0:
                    outfile.write("--- Ping {} ({}) using Python ---\n\n".format(host, dest_addr))
                num_pkts_received += 1
                rtt_arr.append(rtt)
                outfile.write(str(pkt_size) + " bytes from " + dest_addr + ": icmp_seq=" + str(seq_num) +
                              " TTL=" + str(ttl) + " time=" + str(rtt) + " ms\n")
            except TimeoutError as te:
                outfile.write("No response: " + te + "\n")
        '''
        STATS TO REPORT:
            packet loss
            maximum round-trip time
            minimum RTT
            average RTT
            RTT standard deviation
        '''
        outfile.write("\n--- " + host + "(" + dest_addr + ") ping statistics ---\n".format(host, dest_addr))
        if num_pkts_received == 0:
            outfile.write(str(pkts) + " transmitted, 0 received, 100% packet loss\n\n")
        else:
            outfile.write() #todo:finish
    # DONE
    return


if __name__ == "__main__":
    for rir in REGISTRARS:
        ping(rir, 5)
