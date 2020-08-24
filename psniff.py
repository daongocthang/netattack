import argparse

from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
from scapy.packet import Packet, Raw
from scapy.sendrecv import sniff


def sniff_packets(iface=None):
    if iface:
        sniff(filter='port 80', prn=process_packet, iface=iface, store=False)
    else:
        sniff(filter='port 80', prn=process_packet, store=False)


def process_packet(pkt: Packet):
    url = pkt[HTTPRequest].Host.decode() + pkt[HTTPRequest].Path.decode()
    ip = pkt[IP].src
    method = pkt[HTTPRequest].Method.decode()
    print(f'[+] {ip} requested {url} with {method}')
    if show_raw and pkt.haslayer(Raw) and method == 'POST':
        print(f'[*] some useful Raw data: {pkt[Raw]}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', dest='iface', metavar='IFACE')
    parser.add_argument('--show-raw', dest='show_raw', action='store_true')
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw
    sniff_packets(iface)
