#! /usr/bin/env python
# If we don't get all of scapy, packet types are not identified and we end
# up losing a lot of the usefulness.
import scapy.all as scapy
from IPython import embed
from pprint import pprint
import requests


def is_http_or_https_packet(packet):
    if hasattr(packet, 'dport'):
        # We only need to care about the requests' host header, so we can
        # ignore packet.sport since we don't need server replies.
        if packet.dport == 80:
            return 'http'
        if packet.dport == 443:
            return 'https'
    return False


def get_https_host_name(packet):
    # Very naive
    return None


def get_http_host_name(packet):
    # Very naive retriever
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
    packet_type = is_http_or_https_packet(packet)
    if packet_type == 'http':
        host_name = get_http_host_name(packet)
        if host_name:
            visited_http.add(host_name)
    elif packet_type == 'https':
        host_name = get_https_host_name(packet)
        if host_name:
            visited_https.add(host_name)

print('HTTP: %s' % ', '.join(visited_http))
print('HTTPS: %s' % ', '.join(visited_https))
embed()
