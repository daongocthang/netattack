#!/usr/bin/python3

import argparse
import os
import time
from threading import Thread

import scapy.all as scapy
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt

networks = []

root = 'tsudo' if os.uname().nodename == 'localhost' else 'sudo'


def callback(pkt: scapy.Packet):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        ssid = pkt[Dot11Elt].info

        try:
            signal = pkt.dBn_AntSignal
        except:
            signal = 'N/A'

        stats = pkt[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get('crypto')

        networks.append((bssid, signal, channel, crypto, ssid))


def print_all():
    while True:
        os.system('clear')
        hdr = ['BSSID', 'PWR', 'CH', 'ENC', 'SSID']
        print('{h[0]:20}{h[1]:20}{h[2]:20}{h[4]}'.format(h=hdr))
        for data in networks:
            print('{d[0]:20}{d[1]:20}{d[2]:20}{d[4]}'.format(d=data))
        time.sleep(0.5)


def change_channel():
    ch = 1
    while True:
        os.system('{} iwconfig {} channel {}'.format(root, iface, ch))
        ch = ch % 14 + 1
        time.sleep(0.5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', metavar='IFACE', dest='iface')
    args = parser.parse_args()
    iface = args.iface

    printer = Thread(target=print_all, daemon=True)
    printer.start()

    channel_changer = Thread(target=change_channel, daemon=True)
    channel_changer.start()

    scapy.sniff(prn=callback, iface=iface)
