#!/usr/bin/env python3

import sys
from random import randint, choice, seed
import random
from socket import socket, SOCK_DGRAM, AF_INET
import uuid


PORT = 53

DNS_TYPES = {
    'A': 1,
    'AAAA': 28,
    'CNAME': 5,
    'MX': 15,
    'NS': 2,
    'PTR': 12,
    'TXT': 16
}

PUBLIC_DNS_SERVER = [
    '1.0.0.1',  # Cloudflare
    '1.1.1.1',  # Cloudflare
    '8.8.4.4',  # Google
    '8.8.8.8',  # Google
    '8.26.56.26',  # Comodo
    '8.20.247.20',  # Comodo
    '9.9.9.9',  # Quad9
    '64.6.64.6',  # Verisign
    '208.67.222.222',  # OpenDNS
    '208.67.220.220'  # OpenDNS
]

# todo: not sure when to use
def val_to_2_bytes(value: int) -> list:
    '''Split a value into 2 bytes'''
    val_left = value >> 8
    val_right = value & 0xFF
    return [val_left, val_right]

# do not need to use
def val_to_n_bytes(value: int, n_bytes: int) -> list:
    '''Split a value into n bytes'''
    byteLst = []
    shiftedVal = value
    for i in range(n_bytes):
        newVal = shiftedVal & 0xFF
        byteLst.insert(0, newVal)
        shiftedVal = shiftedVal >> 8
    return byteLst

def bytes_to_val(bytes_lst: list) -> int:
    '''Merge 2 bytes into a value'''
    value = 0
    shift = 0
    reshifted = []
    for i in range(len(bytes_lst)-1,-1,-1):
        reshifted.append(bytes_lst[i] << shift)
        shift += 8

    for i in range(len(reshifted)):
        value += reshifted[i]

    return value

# todo: figure out when to use
def get_2_bits(bytes_lst: list) -> int: #co01 look for domain #could be something else
    '''Extract first two bits of a two-byte sequence'''
    return bytes_lst[0] >> 6

def get_offset(bytes_lst: list) -> int:
    '''Extract size of the offset from a two-byte sequence'''
    return ((bytes_lst[0] & 0x3f) << 8) + bytes_lst[1]

def parse_cli_query(filename, q_type, q_domain, q_server=None) -> tuple:
    '''Parse command-line query'''
    if q_type == 'MX':
        raise ValueError('Unknown query type')
    if q_server == None:
        q_server = choice(PUBLIC_DNS_SERVER)
    print(q_server)
    return (DNS_TYPES[q_type], q_domain.split("."), q_server)

def format_query(q_type: int, q_domain: list) -> bytearray:
    transaction_id = random.randint(1, 65000)
    transaction_id_arr = val_to_2_bytes(transaction_id)
    byteArr = bytearray()
    byteArr.append(transaction_id_arr[0])
    byteArr.append(transaction_id_arr[1])
    byteArr.append(1)
    byteArr.append(0)
    byteArr.append(0)
    byteArr.append(1)
    byteArr.append(0)
    byteArr.append(0)
    byteArr.append(0)
    byteArr.append(0)
    byteArr.append(0)
    byteArr.append(0)

    for domain in q_domain:
        byteArr.append(len(domain))
        byteArr = byteArr + bytearray(domain, "utf-8")

    byteArr.append(0)

    q_type_2_bytes = val_to_2_bytes(q_type)
    byteArr.append(q_type_2_bytes[0])
    byteArr.append(q_type_2_bytes[1])

    byteArr.append(0)
    byteArr.append(1)

    return byteArr

def send_request(q_message: bytearray, q_server: str) -> bytes:
    '''Contact the server'''
    client_sckt = socket(AF_INET, SOCK_DGRAM)
    client_sckt.sendto(q_message, (q_server, PORT))
    (q_response, _) = client_sckt.recvfrom(2048)
    client_sckt.close()

    return q_response

def parse_response(resp_bytes: bytes):
    # '''Parse server response'''
    # for i in range(len(resp_bytes)):
    #     print("index: ", i, "value: ", bytes_to_val([resp_bytes[i]]))
    # print("########")
    # print(resp_bytes)
    rr_ans = resp_bytes[7] # two bytes
    offset_index = 12

    # find index of the start of the answers
    while resp_bytes[offset_index] != 0:
        offset_index += 1

    # add 5 to skip over Type and Class, now we found where the answers start
    offset_index += 5

    # let's go go parse the answers!
    parsed_answer = parse_answers(resp_bytes, offset_index, rr_ans)

    return parsed_answer

def parse_answers(resp_bytes: bytes, offset: int, rr_ans: int) -> list:
    '''Parse DNS server answers'''
    # check to see if domain name is in answers, if not, go back to query and grab it
    domain_name = []

    # 12 is the index where the query will always start
    index = 12
    # Get domain name
    while resp_bytes[index] != 0:
        for i in range(1, resp_bytes[index] + 1):
            domain_chr = chr(bytes_to_val([resp_bytes[index + i]]))
            domain_name.append(domain_chr)
        index += resp_bytes[index] + 1
        if resp_bytes[index + 1] != 0:
            domain_name.append(".")

    domain_ttl_addr = []  # list of tuples (domain, ttl, address)

    overall_answer_index = offset

    # domain name included in the answer, have to adjust the overall_answer_index to where parsing begins
    if get_offset([resp_bytes[offset], resp_bytes[offset+1]]) != 12: # todo: this condition may not be right, if 2 bytes == 3 call get_offset
        overall_answer_index = overall_answer_index + len(domain_name)

    addr_len = bytes_to_val([resp_bytes[overall_answer_index+10], resp_bytes[overall_answer_index+11]])
    for i in range(rr_ans):
        # grab ttl
        ttl = bytes_to_val([resp_bytes[overall_answer_index+6], resp_bytes[overall_answer_index+7], \
                                 resp_bytes[overall_answer_index+8], resp_bytes[overall_answer_index+9]])

        # grab IP bytes, send to either parse_address_a or aaaa to get parsed
        addr_bytes = resp_bytes[overall_answer_index+12:overall_answer_index+12+addr_len+1]
        if addr_len == 4:
            addr = parse_address_a(addr_len, addr_bytes)
        elif addr_len == 16:
            addr = parse_address_aaaa(addr_len, addr_bytes)

        # set up index for the next answer to process
        if get_offset([resp_bytes[offset], resp_bytes[offset + 1]]) != 12:  # todo: this condition may not be right
            overall_answer_index += addr_len+12+len(domain_name)
        else:
            overall_answer_index += addr_len+12 # 12 is the number of bytes between the start of the answer and the address byte

        domain_ttl_addr.append(("".join(domain_name), ttl, addr))

    return domain_ttl_addr

def parse_address_a(addr_len: int, addr_bytes: bytes) -> str:
    '''Extract IPv4 address'''
    ip_addr = []
    for i in range(addr_len):
        ip_addr.append(str(bytes_to_val([addr_bytes[i]])))
        if i != addr_len-1:
            ip_addr.append(".")
    return "".join(ip_addr)

# TODO: FINISH!!!
def parse_address_aaaa(addr_len: int, addr_bytes: bytes) -> str:
    '''Extract IPv6 address'''
    # print(addr_bytes)
    # for i in range(addr_len):
    #     print(hex(addr_bytes[i]))
    # print("***")
    ip_addr = ""
    for i in range(addr_len):
        if i != 4 and i != 9 and i != 11 and i != 13 and i != 14: # we don't want to append 00 for column 3 of the ip address
            hex_val = hex(addr_bytes[i])
            hex_slice = hex_val[2:]
            # ip_val = ""

            # accomodate for hex values of 0x1 which is really 01
            # print(hex(addr_bytes[i]), hex_slice)
            if len(hex_slice) == 1 and hex_slice[0] != "0" and i != 15:
                # ip_val = "01"
                ip_addr = ip_addr + "0" + hex_slice
            elif i == 8 or i == 10 or i ==12:
                # ip_val = "0"
                ip_addr = ip_addr + "0"
            else:
                ip_addr = ip_addr + hex_slice

            # place ":" appropriately
            # ":" comes after every odd number and
            if i%2 != 0 and i != 15 or i == 8 or i == 10 or i == 12:
                ip_addr = ip_addr + ":"

            print(i, hex_slice)
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~")

    print(ip_addr)

    # return "".join(ip_addr)

def resolve(query: str) -> None:
    '''Resolve the query'''
    q_type, q_domain, q_server = parse_cli_query(*query[0])
    query_bytes = format_query(q_type, q_domain)
    response_bytes = send_request(query_bytes, q_server)
    answers = parse_response(response_bytes)
    #print('DNS server used: {}'.format(q_server))
    #for a in answers:
        #print('Domain: {}'.format(a[0]))
        #print('TTL: {}'.format(a[1]))
        #print('Address: {}'.format(a[2]))

def main(*query): # *query
    '''Main function'''
    # query = [["resolver.py", "A", "luther.edu", "1.1.1.1"]]
    # print(query)
    if len(query[0]) < 3 or len(query[0]) > 4:
        print('Proper use: python3 resolver.py <type> <domain> <server>')
        exit()
    resolve(query)


if __name__ == '__main__':
    main(sys.argv)
    # main()
