#! /usr/bin/env python
# scapy.all is generated dynamically, stop pylint complaining.
# pylint: disable=E1101
"""
    Example of spoofing IP traffic.
"""
from __future__ import print_function

import argparse
import socket
from sys import stderr, exit

import netifaces

# If we don't get all of scapy, packet types are not identified and we end
# up losing a lot of the usefulness.
import scapy.all as scapy


from arp import arp_query
# res = arp_query(destination, interface)


# Args:
# Target port
# Target IP (on local host)
# Source IP

# TODO: Generate payload
def generate_payload(dest_address):
    tcp = scapy.TCP(
        dport=80,
    )

    http = scapy.Raw(
        load=(
            'GET / HTTP/1.1\r\n'
            'User-Agent: Example\r\n'
            'Host: {dest_address}\r\n'
            'Accept: */*\r\n'
            '\r\n'
        ).format(dest_address=dest_address),
    )

    return tcp / http

def spoof(src, dest, interface):
    # Get the MAC address
    # TODO: Explain why 17
    my_mac = netifaces.ifaddresses(interface)[17]['addr']
    src_mac = arp_query(src, interface)
    if src_mac and src_mac != my_mac:
        # TODO: Complain and exit, someone has this IP

    dest_mac = arp_query(dest, interface):
    if not dest_mac:
        # TODO: Complain and exit
    
    eth = scapy.Ether(
        src=src_mac,
        type='IPv4',
        dst=dest_mac,
    )

    ip = scapy.IP(
        src=src,
        dst=dest,
        version=4,
        proto='tcp',
    )

    payload = generate_payload(dest)

    packet = eth / ip / payload

    result = scapy.srp1(
        packet,
        timeout=5,
        iface=interface,
    )

    return result


if __name__ == '__main__':
    # TODO: Get inputs
    # TODO: Figure out interface?
    # TODO: Add caution note about not doing this on busy networks, you might break something for someone for a while (arp cache time)

    response = spoof(src_ip, dst_ip, interface)

    # TODO: Present response somehow
