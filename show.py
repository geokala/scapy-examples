#! /usr/bin/env python
# If we don't get all of scapy, packet types are not identified and we end
# up losing a lot of the usefulness.
import scapy.all as scapy
import tempfile
import os
import subprocess
# TODO: pylint, import ordering
# TODO: scapy3

ether = scapy.Ether(
    src='fe:ed:ad:ea:dc:0d',
    dst='d0:cd:ae:da:de:ef',
    type=2048,
)

ip = scapy.IP(
    frag=0,
    src='192.168.1.13',
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
    nexthopmtu=None,
    ptr=None,
    unused=None,
    ts_rx=None,
    length=None,
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


if __name__ == '__main__':
    # TODO: Descriptive messages
    packet.show()

    print(packet.summary())

    print(packet.command())

    tempdir = tempfile.mkdtemp()
    dumpfile = os.path.join(tempdir, 'pingpacket')
    packet.psdump(dumpfile)
    # Actually dumps with an eps extension
    dumpfile = dumpfile + '.eps'

    # TODO: Detect OS, use appropriate opening approach
    subprocess.check_call(['xdg-open', dumpfile])

    os.unlink(dumpfile)
    os.rmdir(tempdir)
