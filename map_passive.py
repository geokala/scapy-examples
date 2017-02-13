#! /usr/bin/env python
# If we don't get all of scapy, packet types are not identified and we end
# up losing a lot of the usefulness.
from scapy.all import *  # noqa
from IPython import embed
from pprint import pprint
import requests


# TODO: Get list of IPs and mac addresses on this host
def interesting(packet):
    return True


def get_src_mac(packet):
    layer2 = packet.getlayer(Ether)
    if layer2:
        # If it sent something it's definitely on the network
        # It most likely exists if it's a dst too, but let's be pessimistic
        src = layer2.fields['src']

        vendor_part = src.split(':')[:3]
        vendor_part.extend(('00', '00', '00'))
        return ':'.join(vendor_part)


def get_vendor(mac):
    MAC_URL = 'http://macvendors.co/api/{mac}'
    result = requests.get(MAC_URL.format(mac='BC:92:6B:A0:00:01'))
    return result.json()['result']['company']


def is_multicast(packet):
    if packet.haslayer(IP):
        ip_version = packet.getlayer(IP).fields['version']
        dst = packet.getlayer(IP).fields['dst']

        if ip_version == 4:
            first_octet = int(dst.split('.')[0])
            if 224 <= first_octet <= 239:
                return True
        elif ip_version == 6:
            # Untested, need IPv6 traffic
            high_order = dst[:2].lower()
            if high_order == 'ff':
                return True
    return False

# TODO: stick this in a thread to keep listening, returning packets that are
# interesting (ARP, currently- but get Dot11 for SSID too?), and not storing
# This should result in fairly static memory usage
print('Sniffing for 30 seconds.')
interesting_packets = sniff(
    timeout=30,
    lfilter=interesting,
)

arp_packets = [
    packet for packet in interesting_packets
    if packet.haslayer(ARP)
]
arps = {}
for arp_packet in arp_packets:
    arp = arp_packet.getlayer(ARP)
    arp = (arp.psrc, arp.pdst)
    count = arps.get(arp, 0)
    arps[arp] = count + 1
    # TODO: See which arp destination is highest and doesn't belong to us

multicast_packets = [
    packet for packet in interesting_packets
    if is_multicast(packet)
]

mac_addresses = {
    get_src_mac(packet) for packet in interesting_packets
}
mac_lookup = {
    mac: get_vendor(mac) for mac in mac_addresses
}
pprint(mac_lookup)

# Current results are unhelpful, dig more maybe looking at
# https://pen-testing.sans.org/blog/2011/10/13/special-request-wireless-client-sniffing-with-scapy
embed()
