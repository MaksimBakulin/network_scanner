#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print("IP\t\t\tMAC address\n-----------------------------------------")
    clients_list = []

    for element in answered_list:
        clients_dict = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        clients_list.append(clients_dict)
        print(element[1].psrc + "\t\t" + element[1].hwsrc)
    print(clients_list)

scan('192.168.0.1/24')