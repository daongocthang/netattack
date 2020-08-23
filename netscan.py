import argparse

from scapy.layers.l2 import ARP, Ether, srp


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
        clients.append({'ip': recv.psrc, 'mac': recv.hwsrc})
    return clients


def show(clients):
    hd = 'IP' + ' ' * 20 + 'MAC' + ' ' * 14
    print(hd)
    print('-' * len(hd))
    for elem in clients:
        print('{ip:20}  {mac}'.format(ip=elem['ip'], mac=elem['mac']))


if __name__ == '__main__':
    opt = get_args()
    results = scan(opt.target)
    show(results)
