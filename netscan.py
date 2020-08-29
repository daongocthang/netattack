#!/data/data/com.termux/files/usr/bin/python

import argparse
import shutil

from scapy.layers.l2 import ARP, Ether, srp

OUI_FILE = 'assets/oui.txt'


def manf(bss):
    file = open(OUI_FILE, 'r')
    for line in file.read().splitlines():
        base16 = bss.upper()[:8].replace(':', '')
        if line.startswith(base16):
            return line.split('\t', 1)[1].lstrip('\t')
    return 'unknown'


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', metavar='TARGET', dest='target', help='Specify target one or range of ip')
    return parser.parse_args()


def scan(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    pkt = ether / arp
    res = srp(pkt, timeout=3, verbose=False)[0]
    clients = []
    for sent, recv in res:
        clients.append({'ip': recv.psrc, 'mac': recv.hwsrc, 'vendor': manf(recv.hwsrc)})
    return clients


def show(clients):
    cols = ['IP', 'MAC', 'Vendor']
    print('{c[0]:20}{c[1]:22}{c[2]}'.format(c=cols))
    print('-' * shutil.get_terminal_size().columns)
    for elem in clients:
        print("{p:20}{m:22}{v}".format(p=elem['ip'], m=elem['mac'], v=elem['vendor']))


if __name__ == '__main__':
    opt = get_args()
    results = scan(opt.target)
    show(results)
