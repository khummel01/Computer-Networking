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
        rtt = (time_rcvd-started_select)*1000

        pkt_rcvd, addr = my_socket.recvfrom(1024)
        addr_dst_ip = socket.gethostbyname(addr_dst) # me
        if addr[0] != addr_dst_ip:
            raise ValueError(f"Wrong sender: {addr[0]}")

        # TODO: Extract ICMP header from the IP packet and parse it
        #This function should raise an error if the response mesasge, type, code, or checksum are incorrect

        # 20 bytes of ip stuff, 8 bytes of icmp header
        # ip header: dest_addr, TTL (major thing you want from ip)
        # icmp: type, code, seq_num, checksum <-- check that these match
            # header: Type=0, code=0, checksum

        # conversation with Roman:
        # start Wireshark, look at the ICMP exchange
        # once you receive pkt, zero out the chksum, send (just header?) to checksum function
        # look at htous
        # if type or class is not 0, raise value error, catch in main and report it as a lost packet

        # byte_arr = bytearray(pkt_rcvd) # uncessary
        # ICMP header info
        icmp_header_data = pkt_rcvd[20:]
        icmp_chksum = pkt_rcvd[22:26]
        typ = pkt_rcvd[20]
        code = pkt_rcvd[21]
        #todo: checksum is always 0 for some reason
        # a = byte_arr[20:22]
        # b = byte_arr[24:]
        # icmp_header_without_chksum = a+b
        # print("a: ", a)
        # print("b: ", b)
        # print(icmp_header_without_chksum)

        # print_raw_bytes(pkt_rcvd)

        # Validate type, code, and checksum
        pkt_chksum = checksum(icmp_header_data)
        # validate_chksum = checksum(icmp_header_without_chksum)
        # print("icmp_chksum: ", icmp_chksum, "function chk_sum: ", validate_chksum)
        if typ != ECHO_REPLY_TYPE and code != ECHO_REPLY_CODE: #and icmp_chksum != validate_chksum:
            raise ValueError

        # IP header info
        # dest_addr = byte_arr[16:20] # don't need
        pkt_size = sum(pkt_rcvd[2:4])
        ttl = pkt_rcvd[8]
        seq_num = sum(pkt_rcvd[26:28]) #todo: do we even need this?

        # DONE: End of ICMP parsing
        time_left = time_left - how_long_in_select
        if time_left <= 0:
            raise TimeoutError("Request timed out after 1 sec")

        #todo: return tuple of the destination address, packet size, roundtrip time, time to live, and sequence number
        return (addr_dst_ip, pkt_size, rtt, ttl, seq_num)

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
    with open('output.txt', 'a') as outfile:
        rtt_arr = []
        num_pkts_received = 0
        outfile.write("--- Ping {} ({}) using Python ---\n\n".format(host, socket.gethostbyname(host)))
        for i in range(pkts):
            try:
                dest_addr, pkt_size, rtt, ttl, seq_num = send_request(host, pkts, timeout)
                # if i == 0:
                #     outfile.write("--- Ping {} ({}) using Python ---\n\n".format(host, dest_addr))
                num_pkts_received += 1
                rtt_arr.append(rtt)
                #todo (below): should icmp_seq be passed in?
                outfile.write("{:d} bytes from {}: icmp_seq={:d} TTL={:d} time={:.2f} ms\n".format(pkt_size, dest_addr, i+1, ttl, rtt))

            except TimeoutError as toe:
                outfile.write("No response: " + str(toe) + "\n")
            # except TypeError: pass

        outfile.write("\n--- {} ({}) ping statistics ---\n".format(host, socket.gethostbyname(host)))
        if num_pkts_received == 0:
            outfile.write("{} transmitted, 0 received, 100% packet loss\n\n".format(str(pkts)))
        else:
            packet_loss_perct = 0
            if pkts != num_pkts_received:
                packet_loss_perct = round((1-(num_pkts_received/pkts))*100)
            outfile.write("{:d} packets transmitted, {:d} received, {:d}% packet loss\nrtt "
                          "min/avg/max/mdev = {:.3f}/{:.3f}/{:.3f}/{:.3f} ms\n\n".format(pkts, num_pkts_received,
                            packet_loss_perct, min(rtt_arr), mean(rtt_arr),
                            max(rtt_arr), stdev(rtt_arr)))
    return


if __name__ == "__main__":
    for rir in REGISTRARS:
        ping(rir, 5)
    # ping(REGISTRARS[0], 5)
