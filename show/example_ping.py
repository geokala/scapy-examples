#! /usr/bin/env python
# scapy.all is generated dynamically, stop pylint complaining.
# pylint: disable=E1101
"""
    Example of various ways to display a packet in scapy.
"""
from __future__ import print_function

import argparse
import os
import subprocess
from sys import platform, stderr, exit
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


def display(packet, filters=None):
    """
        Display a packet in various ways.
    """
    if filters is None:
        filters = DISPLAYS.keys()

    for selected in filters:
        if selected in DISPLAYS:
            print('Packet {sel}:'.format(
                sel=selected.replace('_', ' '),
            ))
            DISPLAYS[selected](packet)
        else:
            invalid(selected)


def show_details(packet):
    packet.show()


def show_summary(packet):
    print(packet.summary())


def show_command(packet):
    print(packet.command())


def show_pdf(packet):
    print('Creating and displaying PDF dissection of packet...')
    tempdir = tempfile.mkdtemp()
    dumpfile = os.path.join(tempdir, 'pingpacket')
    packet.psdump(dumpfile)
    # This actually dumps with an eps extension
    dumpfile = dumpfile + '.eps'

    if 'linux' in platform:
        subprocess.check_call(['xdg-open', dumpfile])
    elif platform == 'darwin':
        subprocess.check_call(['open', dumpfile])
    elif platform == 'win32':
        subprocess.check_call(
            'start {dumpfile}'.format(dumpfile=dumpfile),
            shell=True,
        )

    os.unlink(dumpfile)
    os.rmdir(tempdir)


DISPLAYS = {
    'details': show_details,
    'summary': show_summary,
    'creation_code': show_command,
    'pdf': show_pdf,
}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Display packets in... ways.',
    )

    parser.add_argument(
        '-f', '--filter',
        help='Packet displays to show. Allowed {displays}'.format(
            displays=', '.join(DISPLAYS.keys()),
        ),
        nargs='+',
    )

    args = parser.parse_args()

    filters = args.filter
    if filters is not None:
        invalid = []
        for display_filter in filters:
            if display_filter not in DISPLAYS.keys():
                invalid.append(display_filter)
        if invalid:
            stderr.write(
                'Invalid filters specified: {invalid}\n'
                'Valid filters are: {valid}\n'.format(
                    invalid=', '.join(invalid),
                    valid=', '.join(DISPLAYS.keys()),
                )
            )
            exit(1)

    display(make_packet(), filters=filters)
