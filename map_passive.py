#! /usr/bin/env python
from scapy.sendrecv import sniff
from IPython import embed

def interesting(packet):
    return True

print('Sniffing for 30 seconds.')
interesting_packets = sniff(
    timeout=30,
    lfilter=interesting,
)

# Current results are unhelpful, dig more maybe looking at
# https://pen-testing.sans.org/blog/2011/10/13/special-request-wireless-client-sniffing-with-scapy
embed()
