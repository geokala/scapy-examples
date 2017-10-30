#! /usr/bin/env python
# scapy.all is generated dynamically, stop pylint complaining.
# pylint: disable=E1101
"""
    Example of various ways to display a packet in scapy.
"""
from __future__ import print_function

import argparse
import socket
from sys import stderr, exit

import netifaces

# If we don't get all of scapy, packet types are not identified and we end
# up losing a lot of the usefulness.
import scapy.all as scapy


def make_arp_packet(destination, interface, mac_address):
    """
        Make a ping packet for example purposes.
    """
    arp = scapy.ARP(
        hwsrc=mac_address,
        hwtype=1,
        op=1,
        hwlen=6,
        psrc='0.0.0.0',
        plen=4,
        hwdst='ff:ff:ff:ff:ff:ff',
        pdst=destination,
        ptype=2048,
    )

    # Note that the packet.command if you sniff an ARP packet will suggest it
    # needs an Ether layer, but this is incorrect (and more importantly,
    # will not work)
    packet = arp

    return packet


def arp_query(destination, interface):
    """
        Display a packet in various ways.
    """
    # We need the address family with the MAC address
    address_family = netifaces.AF_LINK
    # Get the first MAC address for the interface
    mac_address = netifaces.ifaddresses(interface)[address_family][0]['addr']

    packet = make_arp_packet(destination, interface, mac_address)

    try:
        result = scapy.sr1(packet, timeout=2, iface=interface)
    except socket.error as err:
        if 'No such device' in err:
            stderr.write(
                'Could not use device {interface} as it does not appear '
                'to exist.'.format(
                    interface=interface,
                )
            )
            exit(1)
        print(err)
        raise

    if result:
        print(result.summary())
    else:
        stderr.write(
            'Could not retrieve MAC for IP {ip} on interface '
            '{interface}\n'.format(
                ip=destination,
                interface=interface,
            )
        )
        exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Perform an ARP.',
    )

    parser.add_argument(
        '-d', '--destination',
        help='Destination IPv4 address',
        required=True,
    )

    parser.add_argument(
        '-i', '--interface',
        help='Which interface to ARP from',
        required=True,
        choices=netifaces.interfaces(),
    )

    args = parser.parse_args()

    arp_query(
        destination=args.destination,
        interface=args.interface,
    )
