#!/usr/bin/env python3

import sys
# from random import randint, choice, seed
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


def val_to_2_bytes(value: int) -> list:
    '''Split a value into 2 bytes'''
    val_left = value >> 8
    val_right = value & 0xFF
    return [val_left, val_right]

def val_to_n_bytes(value: int, n_bytes: int) -> list:
    '''Split a value into n bytes'''
    byteLst = []
    shiftedVal = value
    for i in range(n_bytes):
        newVal = shiftedVal & 0xFF
        byteLst.insert(0, newVal)
        shiftedVal = shiftedVal >> 8

    # print(byteLst)
    return byteLst

def bytes_to_val(bytes_lst: list) -> int:
    '''Merge 2 bytes into a value'''
    value = 0
    shift = 0
    reshifted = []
    for i in range(len(bytes_lst)-1,-1,-1):
        reshifted.append(bytes_lst[i] << shift)
        shift += 8
        # print(str(bytes_lst[i]), bytes_lst[i] << shift)

    for i in range(len(reshifted)):
        value += reshifted[i]

    # print(value)
    return value

def get_2_bits(bytes_lst: list) -> int:
    '''Extract first two bits of a two-byte sequence'''
    return bytes_lst[0] >> 6

def get_offset(bytes_lst: list) -> int:
    '''Extract size of the offset from a two-byte sequence'''
    return ((bytes_lst[0] & 0x3f) << 8) + bytes_lst[1]

def parse_cli_query(filename, q_type, q_domain, q_server=None) -> tuple:
    '''Parse command-line query'''
    if q_type == 'MX':
        raise ValueError('Unknown query type')
    # TODO: verify is below is correct
    if q_server == None:
        q_server = PUBLIC_DNS_SERVER[2]
    return (DNS_TYPES[q_type], q_domain.split("."), q_server)

def format_query(q_type: int, q_domain: list) -> bytearray:
    transaction_id = random.randint(1, 60000)
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

    # print(byteArr)
    return byteArr

def send_request(q_message: bytearray, q_server: str) -> bytes:
    '''Contact the server'''
    client_sckt = socket(AF_INET, SOCK_DGRAM)
    client_sckt.sendto(q_message, (q_server, PORT))
    (q_response, _) = client_sckt.recvfrom(2048)
    client_sckt.close()

    return q_response
#################################################HERE!!!#########################################
# todo: how to handle multiple IP addresses?
def parse_response(resp_bytes: bytes):
    # '''Parse server response'''
    for byte in resp_bytes:
        print(byte, chr(bytes_to_val([byte])))
    print("########")

    overall_index = 12
    domain_ttl_addr = []

    answer_bytes_to_parse_ans = []
    while overall_index < len(resp_bytes):
    # for i in range(1): #FOR DEBUGGING PURPOSES ONLY!
        # get domain name
        place = overall_index
        domain_names = []
        if place == 12:
            # Find domain names
            while resp_bytes[place] != 0:
                # print("place: ", place)
                for j in range(1, resp_bytes[place]+1):
                    domain_chr = chr(bytes_to_val([resp_bytes[place+j]]))
                    # print(resp_bytes[place+j], domain_chr)
                    domain_names.append(domain_chr)
                place += resp_bytes[place] + 1
                if resp_bytes[place+1] != 0:
                    domain_names.append(".")
            domain_ttl_addr.append("".join(domain_names))
            overall_index = place + 6 #to get to the answers??

            # print("overall: ", overall_index)
            # print("whereiam: ", resp_bytes[overall_index])

        answer_bytes_to_parse_ans.append(resp_bytes[overall_index])
        overall_index += 1

    # todo: what are we sending to parse_answer? offset where the answer starts? index of c0?
    print(answer_bytes_to_parse_ans)
    # final_answers = parse_answers(answer_bytes_to_parse_ans, )




            # # Parse Answers
            # answer_byte_array = []
            # for i in range(overall_index, len(resp_bytes)) # todo: fix end loop
            #     answer_byte_array.append(resp_bytes[overall_index])
            #     overall_index += 1
            # print(chr(bytes_to_val([resp_bytes[overall_index]])))

    # if respbytes'[placej == 0 or resp_bytes == 1:
    # overindex += 1
    #
    # if respbyesplace == 192:'
    #     ansrlist = []
    #     place +=1

# todo: what is being passed in?, 28->300 in test case
def parse_answers(resp_bytes: bytes, offset: int, rr_ans: int) -> list:
    '''Parse DNS server answers'''
    raise NotImplementedError

def parse_address_a(addr_len: int, addr_bytes: bytes) -> str:
    '''Extract IPv4 address'''
    raise NotImplementedError

def parse_address_aaaa(addr_len: int, addr_bytes: bytes) -> str:
    '''Extract IPv6 address'''
    raise NotImplementedError

def resolve(query: str) -> None:
    '''Resolve the query'''
    q_type, q_domain, q_server = parse_cli_query(*query[0]) # done
    query_bytes = format_query(q_type, q_domain) # in progress
    response_bytes = send_request(query_bytes, q_server) # done
    # val_to_n_bytes(430430, 3)
    # bytes_to_val([6, 145, 94])
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
