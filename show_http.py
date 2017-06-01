#! /usr/bin/env python
# If we don't get all of scapy, packet types are not identified and we end
# up losing a lot of the usefulness.
import scapy.all as scapy
from IPython import embed
from pprint import pprint
import requests


def is_http_or_https_packet(packet):
    if hasattr(packet, 'sport'):
        if 80 in (packet.sport, packet.dport):
            return True
        #if 443 in (packet.sport, packet.dport):
        #    return True
    return False


def get_http_host_name(packet):
    # Very naive retriever
    # TODO Needs to handle zipped
    hostname = None
    if packet.haslayer('Raw'):
        fields = packet.getlayer('Raw').load.split('\r\n')
        for field in fields:
            if field.startswith('Host: '):
                hostname = field[6:].strip()
    return hostname


listen_time = 30
print('Sniffing for {time} seconds.'.format(time=listen_time))
http_packets = scapy.sniff(
    timeout=listen_time,
    lfilter=is_http_or_https_packet,
)

visited_http = set()
visited_https = set()

for packet in http_packets:
    if 80 in (packet.sport, packet.dport):
        host_name = get_http_host_name(packet)
        if host_name:
            visited_http.add(host_name)

# Current results are unhelpful, dig more maybe looking at
# https://pen-testing.sans.org/blog/2011/10/13/special-request-wireless-client-sniffing-with-scapy
embed()
