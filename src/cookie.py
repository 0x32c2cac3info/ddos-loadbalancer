# !/usr/local/bin/python

import time
from scapy.layers.inet import IP, TCP
import socket

import siphash
from binascii import hexlify

MAX_SYNCOOKIE_AGE = 2
COOKIEBITS = 24
COOKIEMASK = int(24 * '1', 2)


def ip_to_int(addr):
    ll = addr.split(".")
    ll = list(map(int, ll))
    return ll[0] * (256 ** 3) + ll[1] * (256 ** 2) + ll[2] * (256 ** 1) + ll[3]


def cookie_hash(saddr, daddr, sport, dport, count, key):
    key = int(4 * str(hex(key))[2:], 16).to_bytes(16, byteorder='big')

    a = socket.htonl(ip_to_int(saddr))
    b = socket.htonl(ip_to_int(daddr))
    c = (socket.htons(sport) << 16) | socket.htons(dport)
    d = count

    return int.from_bytes(siphash.siphash_64(key, ((b << 96) | (a << 64) | (d << 32) | c)
                                             .to_bytes(16, byteorder='big')), 'big') & int(32 * '1', 2)


def get_cookie_time():
    return (int(time.time()) >> 6) & int(0xFF)


def cookie_check(ip, tcp, key):
    seq = tcp.seq - 1
    cookie = tcp.ack - 1
    count = get_cookie_time()
    cookie -= cookie_hash(ip.src, ip.dst, tcp.sport, tcp.dport, 0, key) + seq
    diff = (count - (cookie >> COOKIEBITS)) & int(0xFF)
    if diff >= MAX_SYNCOOKIE_AGE:
        return None

    return (cookie - cookie_hash(ip.src, ip.dst, tcp.sport, tcp.dport,
                                 count - diff, key)) & int(16 * '1', 2)


def cookie_create(ip, tcp, seq, data, key):
    count = get_cookie_time()
    return (cookie_hash(ip.src, ip.dst, tcp.sport, tcp.dport, 0, key) + \
           seq + (count << COOKIEBITS) + \
           ((cookie_hash(ip.src, ip.dst, tcp.sport, tcp.dport, count, key) + data) & COOKIEMASK)) & int(32 * '1', 2)
