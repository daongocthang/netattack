#!/usr/bin/python3


import argparse
import os
import shutil
import time

import pywifi


AKM = ['NONE', 'WPA', 'WPA/PSK', 'WPA2', 'WPA2/PSK', 'UNKNOWN']
CIPHER = ['NONE', 'WEP', 'TKIP', 'CCMP', 'UNKNOWN']
AUTH = ['OPEN', 'SHARED']


def get_ifaces():
    w = pywifi.PyWiFi()
    return w.interfaces()


def scan(iface):
    iface.scan()
    time.sleep(5)
    bsses = iface.scan_results()
    closed = []
    networks = []
    for bss in bsses:
        if bss.bssid in closed:
            continue
        closed.append(bss.bssid)
        networks.append((
            bss.bssid,
            bss.ssid,
            bss.freq,
            bss.signal,
            bss.cipher,
            bss.akm
        ))
    return sorted(networks, key=lambda st: st[3], reverse=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', metavar='FILTER', dest='filter', default='')

    opt = parser.parse_args()

    iface = get_ifaces()[0]
    if not iface:
        print('[-] cannot found wlan interface')
        os._exit(0)

    try:
        while True:
            results = scan(iface)

            if os.name == 'nt':
                _ = os.system('cls')
            else:
                _ = os.name('clear')

            print("{:7}{:22}{:8}{:8}{:12}{:11}{}".format('ID', 'BSSID', 'FREQ', 'PWR', 'ENC', 'CIPHER', 'SSID'))
            max_width = shutil.get_terminal_size().columns
            print('-' * max_width)

            i = 0
            for res in results:
                if opt.filter not in res[1]:
                    continue

                i = i + 1

                bssid = res[0][:-1]
                ssid = res[1]
                freq = res[2] / 1000000
                signal = res[3]
                akm = AKM[res[5][0]]
                auth = AUTH[res[4]]

                print("{:<7}{:22}{:<8}{:<8}{:<12}{:11}{}".format('%2d' % i, bssid, freq, signal, akm, auth, ssid))

    except KeyboardInterrupt:
        pass
