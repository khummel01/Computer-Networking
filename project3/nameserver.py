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
    # {domain: [(ttl, class, type, address)]}
    zone_dict = dict()
    with open(filename) as zone_file:
        origin = zone_file.readline().split()[1].rstrip('.')
        default_ttl = zone_file.readline().split()[1]

        previous_domain = None
        for line in zone_file:
            line = line.split()
            domain = line[0]
            # Nothing is missing, we all good here
            if len(line) == 5:
                zone_dict[domain] = [(line[1], line[2], line[3], line[4])]
                previous_domain = domain
            elif len(line) == 4:
                # TTL is missing, known domain
                if domain in zone_dict:
                    zone_dict[domain].append((default_ttl, line[1], line[2], line[3]))
                # TTL is missing, new domain
                elif domain not in TTL_SEC:
                    zone_dict[domain] = [(default_ttl, line[1], line[2], line[3])]
                    previous_domain = domain
                # Domain is missing
                else:
                    zone_dict[previous_domain].append((line[0], line[1], line[2], line[3]))
            # Both domain and TTL are missing
            else:
                zone_dict[previous_domain].append((default_ttl, line[0], line[1], line[2]))

    return (origin, zone_dict)


def parse_request(origin: str, msg_req: bytes) -> tuple:
    '''Parse the request'''
    # return tuple of (transaction_id, domain, query type, query)
    transaction_id = bytes_to_val([msg_req[0], msg_req[1]])

    overall_index = 12
    domain_name = ""

    # get domain name
    for i in range(1, msg_req[overall_index] + 1):
        domain_chr = chr(bytes_to_val([msg_req[overall_index + i]]))
        domain_name = domain_name + domain_chr
        print(bytes_to_val([msg_req[overall_index + i]]), domain_chr)
        overall_index += msg_req[overall_index] + 1

    # find index where domain name ends
    while msg_req[overall_index] != 0:
        overall_index += 1

    # todo: raise value error if the type, class, or zone (origin) cannot be processed
    type = bytes_to_val([msg_req[overall_index+1], msg_req[overall_index+2]])
    clas = bytes_to_val([msg_req[overall_index+3], msg_req[overall_index+4]])

    return (transaction_id, domain_name, type, msg_req[12:])


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
        print("here")
        (request_msg, client_addr) = server_sckt.recvfrom(512)
        print(request_msg)
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
