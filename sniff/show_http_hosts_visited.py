#! /usr/bin/env python
##############################################################################
# Example script for sniff functionality with automatic output of packets.
# Shows each HTTP or HTTPS (assuming SNI is used) hostname visited on the
# local machine while it is running.
# Note that the command specified by prn is run asynchronously so any
# extensions will likely need to make use of locking, etc.
##############################################################################
# If we don't get all of scapy, packet types are not identified and we end
# up losing a lot of the usefulness.
import scapy.all as scapy
import sys


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
    raw_packet = packet.getlayer('Raw')
    if raw_packet:
        raw_packet = raw_packet.load
    else:
        raw_packet = []
    hostname = None

    if sys.version[0] == '3':
        packet_bytes = [byte for byte in raw_packet]
    else:
        packet_bytes = [ord(byte) for byte in raw_packet]

    # We only currently handle TLS
    # This has first bytes:
    # 0x16 (ssl handshake)
    # 0x03 (TLS)
    # 0x01 (v1)
    if packet_bytes[0:3] == [0x16, 0x03, 0x01]:
        # The next two bytes will be length, which we don't care about here
        packet_bytes = packet_bytes[5:]

        # The next byte should be a client hello (0x01) for the packet we want
        if packet_bytes[0] == 0x1:
            # Next three bytes will be length, which we don't care about
            # Then two bytes for version (e.g. 0x03, 0x03 for TLSv1.2)
            # This is followed by 4 bytes for the current system time
            # Then 28 bytes of 'random'
            # For our purposes we can discard all of this data
            packet_bytes = packet_bytes[38:]

            # Now we have the 1 byte session ID length followed by session ID
            session_id_length = packet_bytes[0]
            # Discard the length and session ID
            packet_bytes = packet_bytes[session_id_length + 1:]

            # Now we have the 2 bytes cipher suites length followed by suites
            cipher_suites_length = packet_bytes[1] + 256 * packet_bytes[0]
            # Discard the length and cipher suites
            packet_bytes = packet_bytes[cipher_suites_length + 2:]

            # Now the compression methods length and compression methods
            compression_methods_length = packet_bytes[0]
            # Discard the length and compression methods
            packet_bytes = packet_bytes[compression_methods_length + 1:]

            # Next is two bytes for extensions length, which we can discard
            # as we will just be checking each extension for the one we want
            # and the length is bound within the python array anyway.
            packet_bytes = packet_bytes[2:]

            while len(packet_bytes) > 0:
                # Each extension starts with its type
                # SNI (server name identification) is 0x00, 0x00
                if packet_bytes[:2] == [0x00, 0x00]:
                    # The next two bytes are extension length, which does not
                    # interest us, so we get rid of them and the type
                    packet_bytes = packet_bytes[4:]

                    # The next two bytes are the SNI list length
                    # TODO: Be less naive in dealing with this
                    packet_bytes = packet_bytes[2:]
                    if packet_bytes[0] == 0x00:
                        # This is a hostname, good!
                        name_length = packet_bytes[2] + 256 * packet_bytes[1]
                        packet_bytes = packet_bytes[3:]
                        hostname = packet_bytes[:name_length]
                        packet_bytes = packet_bytes[name_length:]
                        hostname = ''.join([chr(char) for char in hostname])
                    else:
                        # What is this?
                        sys.stderr.write('Could not determine SNI type\n')
                        sys.stderr.write('%s\n' % packet_bytes)
                else:
                    # The next two bytes are the length, and we don't need
                    # this extension so we will discard it
                    extension_length = packet_bytes[3] + 256 * packet_bytes[2]
                    # Discard the entire extension
                    packet_bytes = packet_bytes[extension_length + 4:]

    return hostname


def get_http_host_name(packet):
    # Very naive retriever
    hostname = None
    if packet.haslayer('Raw'):
        if sys.version[0] == '3':
            raw_packet = str(packet.getlayer('Raw').load, 'ascii')
        else:
            raw_packet = packet.getlayer('Raw').load
        fields = raw_packet.split('\r\n')
        for field in fields:
            if field.startswith('Host: '):
                hostname = field[6:].strip()
    return hostname


def get_target_host(packet):
    packet_type = is_http_or_https_packet(packet)
    host_name = None

    if packet_type == 'http':
        host_name = get_http_host_name(packet)
    elif packet_type == 'https':
        host_name = get_https_host_name(packet)

    if host_name:
        return '{packet_type}: {host}'.format(
            packet_type=packet_type,
            host=host_name,
        )


if __name__ == '__main__':
    print('Sniffing until stopped...')
    print('Ctrl+C is your friend!')
    scapy.sniff(
        prn=get_target_host,
    )
