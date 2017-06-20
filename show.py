#! /usr/bin/env python
# scapy.all is generated dynamically, stop pylint complaining.
# pylint: disable=E1101
"""
    Example of various ways to display a packet in scapy.
"""
from __future__ import print_function
import os
import subprocess
import tempfile

# If we don't get all of scapy, packet types are not identified and we end
# up losing a lot of the usefulness.
import scapy.all as scapy


def make_packet():
    """
        Make a ping packet for example purposes.
    """
    ether = scapy.Ether(
        src='fe:ed:ad:ea:dc:0d',
        dst='d0:cd:ae:da:de:ef',
        type=2048,
    )

    ip = scapy.IP(  # pylint: disable=invalid-name
        frag=0,
        src='192.0.2.201',
        proto=1,
        tos=0,
        dst='8.8.8.8',
        chksum=22360,
        len=84,
        options=[],
        version=4,
        flags=2,
        ihl=5,
        ttl=64,
        id=4492,
    )

    icmp = scapy.ICMP(
        gw=None,
        code=0,
        ts_ori=None,
        addr_mask=None,
        seq=101,
        ptr=None,
        unused=None,
        ts_rx=None,
        chksum=49274,
        reserved=None,
        ts_tx=None,
        type=8,
        id=3408,
    )

    data = scapy.Raw(
        load='some-data',
    )

    packet = ether/ip/icmp/data

    return packet


def display(packet):
    """
        Display a packet in various ways.
    """
    print('Packet details:')
    packet.show()

    print('Packet summary:')
    print(packet.summary())

    print('Python code to create packet:')
    print(packet.command())

    print('Creating and displaying PDF dissection of packet...')
    tempdir = tempfile.mkdtemp()
    dumpfile = os.path.join(tempdir, 'pingpacket')
    packet.psdump(dumpfile)
    # This actually dumps with an eps extension
    dumpfile = dumpfile + '.eps'

    # TODO: Detect OS, use appropriate opening approach
    subprocess.check_call(['xdg-open', dumpfile])

    os.unlink(dumpfile)
    os.rmdir(tempdir)


if __name__ == '__main__':
    display(make_packet())
