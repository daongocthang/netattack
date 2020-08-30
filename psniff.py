#!/usr/bin/python3

import argparse
import time
from datetime import datetime as dt

import scapy.all as scapy
from scapy.layers.http import HTTPRequest


def sniff_packets(iface=None):
    if iface:
        scapy.sniff(filter='port 80', prn=process_packet, iface=iface, store=False)
    else:
        scapy.sniff(filter='port 80', prn=process_packet, store=False)


def process_packet(pkt: scapy.Packet):
    if pkt.haslayer(HTTPRequest):
        url = pkt[HTTPRequest].Host.decode() + pkt[HTTPRequest].Path.decode()

        method = pkt[HTTPRequest].Method.decode()
        print(
            '[{t}][{m}] HTTP Request >> {u}'.format(t=dt.now().strftime('%Y-%m-%d %H:%M:%S'), u=url, m=method))

        if show_raw and pkt.haslayer(scapy.Raw) and method == 'POST':
            raw = pkt[scapy.Raw]
            print(f'[*] Raw data: {raw.load}')

        time.sleep(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', dest='iface', metavar='IFACE')
    parser.add_argument('--show-raw', dest='show_raw', action='store_true')

    args = parser.parse_args()

    iface = args.iface
    show_raw = args.show_raw

    sniff_packets(iface)
