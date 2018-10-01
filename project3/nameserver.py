'''
DNS Name Server
'''
#!/usr/bin/env python3

import sys
from random import randint, choice
from socket import socket, SOCK_DGRAM, AF_INET


HOST = "localhost"
PORT = 43053

DNS_TYPES = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA'
}

TTL_SEC = {
    '1s': 1,
    '1m': 60,
    '1h': 60*60,
    '1d': 60*60*24,
    '1w': 60*60*24*7,
    '1y': 60*60*24*365
    }


def val_to_bytes(value: int, n_bytes: int) -> list:
    '''Split a value into n bytes'''
    byteLst = []
    shiftedVal = value
    for i in range(n_bytes):
        newVal = shiftedVal & 0xFF
        byteLst.insert(0, newVal)
        shiftedVal = shiftedVal >> 8
    return byteLst


def bytes_to_val(bytes_lst: list) -> int:
    '''Merge n bytes into a value'''
    value = 0
    shift = 0
    reshifted = []
    for i in range(len(bytes_lst)-1, -1, -1):
        reshifted.append(bytes_lst[i] << shift)
        shift += 8

    for i in range(len(reshifted)):
        value += reshifted[i]

    return value

def get_left_bits(bytes_lst: list, n_bits: int) -> int:
    '''Extract left n bits of a two-byte sequence'''
    val = bytes_to_val(bytes_lst)
    return int(bin(val)[2:n_bits+2], 2)


def get_right_bits(bytes_lst: list, n_bits) -> int:
    '''Extract right n bits bits of a two-byte sequence'''
    val = bytes_to_val(bytes_lst)
    return int(bin(val)[-n_bits:], 2)


def read_zone_file(filename: str) -> tuple:
    '''Read the zone file and build a dictionary'''
    # build a dictionary of domain names
    # todo: ask: {domain_name: IP_address}?
    zone = dict()
    with open(filename) as zone_file:
        origin = zone_file.readline().split()[1].rstrip('.')
        print(origin)
    
    return (origin, zone)


def parse_request(origin: str, msg_req: bytes) -> tuple:
    '''Parse the request'''
    raise NotImplementedError


def format_response(zone: dict, trans_id: int, qry_name: str, qry_type: int, qry: bytearray) -> bytearray:
    '''Format the response'''
    raise NotImplementedError


def run(filename: str) -> None:
    '''Main server loop'''
    server_sckt = socket(AF_INET, SOCK_DGRAM)
    server_sckt.bind((HOST, PORT))
    origin, zone = read_zone_file(filename)
    print("Listening on %s:%d" % (HOST, PORT))

    while True:
        (request_msg, client_addr) = server_sckt.recvfrom(512)
        try:
            trans_id, domain, qry_type, qry = parse_request(origin, request_msg)
            msg_resp = format_response(zone, trans_id, domain, qry_type, qry)
            server_sckt.sendto(msg_resp, client_addr)
        except ValueError as ve:
            print('Ignoring the request: {}'.format(ve))
    server_sckt.close()


def main(*argv):
    '''Main function'''
    if len(argv[0]) != 2:
        print('Proper use: python3 nameserver.py <zone_file>')
        exit()
    run(argv[0][1])


if __name__ == '__main__':
    main(sys.argv)
