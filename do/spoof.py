#! /usr/bin/env python
# scapy.all is generated dynamically, stop pylint complaining.
# pylint: disable=E1101
"""
    Example of spoofing IP traffic.
"""
from __future__ import print_function

import argparse
from sys import stderr, exit

import netifaces

# If we don't get all of scapy, packet types are not identified and we end
# up losing a lot of the usefulness.
import scapy.all as scapy


from arp import arp_query


def generate_payload(dest_address):
    # TODO: This is a reasonably complicated payload; maybe try an ICMP Echo Request?
    tcp = scapy.TCP(
        dport=8000,
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


class IPAddressInUseError(Exception):
    pass


class IPAddressNotFoundError(Exception):
    pass


def spoof(src_ip, dest_ip, interface):
    # Get the MAC address
    # We want MACs, which are from the 'PACKET' Address Family (AF_PACKET)
    my_macs = [
        details['addr']
        for details in netifaces.ifaddresses(interface)[netifaces.AF_PACKET]
    ]
    # Get local IPs, because we probably won't respond to an ARP from ourself
    # We want IPs, which are from the 'INET' Address Family (AF_INET)
    my_ips = [
        details['addr']
        for details in netifaces.ifaddresses(interface)[netifaces.AF_INET]
    ]
    src_mac = arp_query(src_ip, interface)
    if src_mac and src_mac not in my_macs:
        # Of course, if we were doing something nefarious we could skip this
        # check, just so long as we poisoned both ends of the connection and
        # allowed the packets we were then intercepting to pass through.
        # For example purposes, we won't do that because there's a good chance
        # that the first time you try this you'll end up swallowing lots of
        # packets or otherwise doing something with unfortunate side effects.
        raise IPAddressInUseError(
            'Cannot use IP address {src} as a source IP, as this address '
            'appears to already be in use on the network.'.format(
                src=src_ip,
            )
        )

    dest_mac = arp_query(dest_ip, interface)
    if not dest_mac:
        if dest_ip in my_ips:
            dest_mac = my_macs[0]
        else:
            raise IPAddressNotFoundError(
                'Cannot send spoofed traffic to {dest}, as this IP address '
                'does not appear to be active on the network.'.format(
                    dest=dest_ip,
                )
            )

    # Spoof the source IP
    gratuitous_arp(src_mac, dest_mac, src_ip, dest_ip, interface)

    eth = scapy.Ether(
        src=src_mac,
        type='IPv4',
        dst=dest_mac,
    )

    ip = scapy.IP(
        src=src_ip,
        dst=dest_ip,
        version=4,
        proto='tcp',
    )

    payload = generate_payload(dest_ip)

    packet = eth / ip / payload

    result = scapy.srp1(
        packet,
        timeout=5,
        iface=interface,
    )

    return result


def gratuitous_arp(src_mac, dst_mac, src_ip, dst_ip, interface):
    eth = scapy.Ether(
        src=src_mac,
        dst=dst_mac,
        type=2054,  # TODO: We can look this up from somewhere, but not for OSX?
    )

    arp = scapy.ARP(
        hwlen=6,  # TODO: Explain this
        hwsrc=src_mac,
        hwdst=dst_mac,
        hwtype=1,  # TODO: Where do we look this up?
        ptype=2048,  # TODO Where do we look this up?
        psrc=src_ip,
        pdst=dst_ip,
        op=2,  # TODO: Explain this too
    )

    packet = eth / arp

    scapy.sendp(packet, iface=interface)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=(
            'Spoof source address. '
            'Designed to be used with the included examplehttpserver. '
            'CAUTION: Do not run this on busy networks or ones which you '
            'will be sad to see temporarily unhealthy. '
            'If something goes wrong and the built-in protections do not '
            'function correctly then the network may become unhealthy for '
            'up to the time it takes for ARP caches to expire on devices '
            'on this network. This can be several hours for routers!'
        ),
    )

    parser.add_argument(
        '-s', '--source',
        help='Source IP address.',
        required=True,
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

    response = spoof(
        src_ip=args.source,
        dest_ip=args.destination,
        interface=args.interface,
    )

    if response:
        print(response.summary())
    else:
        stderr.write(
            'No response received. Check that the target server is up and '
            'responding, and that the network interface you specified is '
            'correct and not currently down.'
        )
        exit(1)
