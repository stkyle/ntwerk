# -*- coding: utf-8 -*-
"""
Created on Sat Jul  4 12:37:00 2015

@author: steve
"""
import socket
from struct import unpack
import logging
import time

logging.basicConfig()


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

FRAME_HEADER_FMT = '!6s6sH'  # Big-Endian 6 byte str, 6 byte str, 2 byte int
ETH_P_ALL = 0x0003


def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
        ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


def get_virgin_socket():
    """Ceate Raw Packet Socket (with undefined header and protocol)"""
    ETH_P_ALL = 0x0003
    try:
        s = socket.socket(socket.AF_PACKET,
                          socket.SOCK_RAW,
                          socket.ntohs(ETH_P_ALL))
        return s

    except socket.error, msg:
        err_log = 'Socket Error: %s, Code: %s' % (msg[1], msg[0])
        log.error(err_log)
        raise EnvironmentError(err_log)


class EthernetFrame(object):

    def __init__(self, packet):
        pass


s = get_virgin_socket()

def get_c(hex_str):
    ret_str = []
    for c in hex_str:
        k = int(c,16)
        if k<128:
            ret_str += [c.decode("hex")]
        else:
            ret_str += ['.']
    return ret_str

# A data packet on an Ethernet link is called an Ethernet packet, which
# transports an Ethernet frame as its payload
buffer_size = 65565  # 66 Bytes
import binascii, re

while True:
    sock_data, sock_addr = s.recvfrom(buffer_size)  # returns (str,n-tuple)
    sock_interface, sock_port = sock_addr[:2]
    frm_dest = sock_data[0:6]
    frm_src = sock_data[6:12]
    eth_typ = unpack('!H', sock_data[12:14])[0]
    payload = sock_data[14:]
    # print pr
    # eth_protocol = socket.ntohs(pr)
    # print eth_protocol
    # print( "{0:#0{1}x}".format(hex(sock_data[13]),6))
    b12 = sock_data[12]
    b13 = sock_data[13]

    frm_dest_hex = binascii.hexlify(frm_dest)
    frm_src_hex = binascii.hexlify(frm_src)
    frm_dest_int = int(frm_dest_hex, 16)
    frm_src_int = int(frm_src_hex, 16)

    if not(all([frm_dest_int, frm_src_int])):
        continue

    print('byte 13: 0x%s ' % b12.encode('hex'))
    print('byte 14: 0x%s ' % b13.encode('hex'))
    print('Interface: %s' % sock_interface)
    print('Destination: %s' % eth_addr(frm_dest))
    print('Source: %s' % eth_addr(frm_src))
    print('EtherType: %s' % "{0:#0{1}x}".format(eth_typ, 6))
    # print eth_typ

    if eth_typ != 2048:
        continue

    proto_offset = 8 * 8 + 8
    ip_proto = payload[proto_offset:proto_offset + 8]
    # print ip_proto
    # print binascii.hexlify(payload[0])

    fmt = '!B'  # 1 byte
    iph = unpack(fmt, payload[0])[0]
    # print 'Big-Endian Byte: %s' % iph
    # print 'Big-Endian Byte: %s' % bin(iph)
    vesion_bin = bin(iph)[2:-4].zfill(4)
    version_int = int(vesion_bin, 2)  # bin->dec, base 2
    #vesion_bin = (4-len(vesion_bin))*'0' + vesion_bin
    print 'Version (First Four Bits): %s (%s)' % (vesion_bin, version_int)

    ihl_bin = bin(iph)[-4:]
    ihl_int = int(ihl_bin, 2)
    print 'IHL (Second Four Bits): %s (%s)' % (ihl_bin, ihl_int)
    print

    ip_header = payload[:20]
    fmt = '!BBHHHBBH4s4s'
    iph = unpack(fmt, ip_header)
    protocol = iph[6]
    print 'Protocol: %s' % protocol
    print ' Source; %s' % socket.inet_ntoa(iph[8])
    print ' Dest; %s' % socket.inet_ntoa(iph[9])

    for i in range(0,256,16):
        text = payload[i:i+16]
        #print [ord(q) for q in text]
        sum_line = ''.join([q if 32 <ord(q) < 128 else '.' for q in text])
        # str(unichr(97))
        #print ' '.join([hd.encode('hex') for hd in payload[i:i+16]]) + ' | ' + payload[i:i+16]
        print ' '.join([hd.encode('hex') for hd in payload[i:i+16]]) + ' | ' + sum_line

#    print ' '.join([hd.encode('hex') for hd in payload[16:32]])
#    print ' '.join([hd.encode('hex') for hd in payload[32:32+16]])
#    print(payload[0].encode('hex'))
#    print(payload[1].encode('hex'))
#    print(payload[2].encode('hex'))
#    print(payload[3].encode('hex'))
#    
#    print(payload[32].encode('hex'))
#    print(payload[33].encode('hex'))
#    print(payload[34].encode('hex'))
#    print(payload[35].encode('hex'))
#    print(payload[36].encode('hex'))
#    print(payload[37].encode('hex'))
#
#    print(payload[38].encode('hex'))
#    print(payload[39].encode('hex'))
#    print(payload[40].encode('hex'))
#    print(payload[41].encode('hex'))
#    print(payload[42].encode('hex'))
#    print(payload[43].encode('hex'))
    
    
    time.sleep(3)


class EthernetHeader(object):

    """Each Ethernet frame starts with an Ethernet header, which contains
    destination and source MAC addresses as its first two fields."""

    def __init__(self, packet):
        # strip and unpack first 14 bytes
        _header = unpack(FRAME_HEADER_FMT, packet[:14])
        self.dst_mac = _header[0]  # 6 byte str
        self.src_mac = _header[1]  # 6 byte str
        self.eth_typ = _header[2]  # 2 byte int
        self.eth_tag = None

    # The EtherType field is two octets long and it can be used for two
    # different purposes. Values of 1500 and below mean that it is used
    # to indicate the size of the payload in octets, while values of 1536
    # and above indicate that it is used as an EtherType, to indicate which
    # protocol is encapsulated in the payload of the frame. When used as
    # EtherType, the length of the frame is determined by the location of
    # the interpacket gap and valid frame check sequence (FCS).

    # The IEEE 802.1Q tag, if present, is a four-octet field that indicates
    # Virtual LAN (VLAN) membership and IEEE 802.1p priority.


class EthernetPayload(object):

    """The middle section of the frame is payload data including any headers
    for other protocols (for example, Internet Protocol) carried in the
    frame. """

    def __init__(self, packet):
        pass


class EthernetFrameCeckSequence(object):

    """The frame ends with a frame check sequence (FCS), which is a 32-bit
    cyclic redundancy check used to detect any in-transit corruption of
    data."""
