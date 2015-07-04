# -*- coding: utf-8 -*-
"""
Created on Thu Jul  2 18:24:56 2015

A socket is one endpoint of a communication channel used by programs to pass
data back and forth locally or across the Internet. Sockets have two primary
properties controlling the way they send data:
    - the address family controls the OSI network layer protocol used
    - the socket type controls the transport layer protocol.

AF_INET
-------
Python supports three address families. The most common, AF_INET, is used for
IPv4 Internet addressing. IPv4 addresses are made up of four octal values
separated by dots (e.g., 10.1.1.5 and 127.0.0.1). These values are more
commonly referred to as “IP addresses.” Almost all Internet networking is done
using IP version 4 at this time.

AF_INET6
-------
AF_INET6 is used for IPv6 Internet addressing. IPv6 is the “next generation”
version of the Internet protocol, and supports 128-bit addresses, traffic
shaping, and routing features not available under IPv4. Adoption of IPv6 is
still limited, but continues to grow.

AF_UNIX
-------
AF_UNIX is the address family for Unix Domain Sockets (UDS), an interprocess
communication protocol available on POSIX-compliant systems. The
implementation of UDS typically allows the operating system to pass data
directly from process to process, without going through the network stack.
This is more efficient than using AF_INET, but because the filesystem is used
as the namespace for addressing, UDS is restricted to processes on the same
system. The appeal of using UDS over other IPC mechanisms such as named pipes
or shared memory is that the programming interface is the same as for IP
networking, so the application can take advantage of efficient communication
when running on a single host, but use the same code when sending data across
the network.

Note The AF_UNIX constant is only defined on systems where UDS is supported.
The socket type is usually either SOCK_DGRAM for user datagram protocol (UDP)
or SOCK_STREAM for transmission control protocol (TCP). UDP does not require
transmission handshaking or other setup, but offers lower reliability of
delivery. UDP messages may be delivered out of order, more than once, or not
at all. TCP, by contrast, ensures that each message is delivered exactly once,
and in the correct order. Most application protocols that deliver a large
amount of data, such as HTTP, are built on top of TCP. UDP is commonly used
for protocols where order is less important (since the message fits in a
single packet, i.e., DNS), or for multicasting (sending the same data to
several hosts).
"""

WAIT_INTERVAL = 5  # seconds

import platform
import socket
import sys
from struct import *
import time
from uuid import getnode
import fcntl
import logging

logging.basicConfig()


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

#struct.unpack(fmt, string)
#Unpack the string (presumably packed by pack(fmt, ...)) according to the
#given format. The result is a tuple even if it contains exactly one item.
#The string must contain exactly the amount of data required by the
#format (len(string) must equal calcsize(fmt)).

def get_pyversion():
    """return version number (major, minor, micro) release"""
    return sys.version_info[0:3]


def get_constants(prefix):
    """Create a dictionary mapping socket module constants to their names."""
    return dict((getattr(socket, n), n)
                for n in dir(socket)
                if n.startswith(prefix))


def get_addr_families():
    families = get_constants('AF_')
    return families


def get_socket_types():
    sock_types = get_constants('SOCK_')
    return sock_types


def get_ip_protocols():
    protocols = get_constants('IPPROTO_')
    return protocols


def get_mac():
    """returns uppercase hex with each byte separated by a colon"""
    mac_int = getnode()  # Get the hardware address as a 48-bit pos. integer
    oldskool_mac = ':'.join(
        ('%012X' % mac_int)[i:i + 2] for i in range(0, 12, 2))
    return oldskool_mac


def get_ip_addr(ifname):
    """given network interface adapter name, return IP

    Args:
        ifname (str): Network Adapter Alias (usually `eth0` or `lo`)
    """
    SIOCGIFADDR = 0x8915
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip_str = socket.inet_ntoa(
        fcntl.ioctl(s.fileno(),
                    SIOCGIFADDR,
                    struct.pack('256s', ifname[:15]))[20:24])
    return ip_str


mac_addr = get_mac()
print(mac_addr)


platform_name = platform.node()
print(platform_name)

# Get the System Host Name
host_name = socket.gethostname()
print(host_name)

# Get Domain Name
domain_name = socket.getfqdn()
print(domain_name)

ip_num = socket.gethostbyname(host_name)
print(ip_num)

print('\n' * 10)  # Clear 10 lines
# Convert a string of 6 characters of ethernet address into a dash
# separated hex string


def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
        ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


def get_virgin_socket():
    ETH_P_ALL = 0x0003  # Every packet (be careful!!!) */
    try:
        # Convert 16-bit positive integers from network to host byte order.
        # Ethernet Protocol ID corresponding to ALL packets
        # Ceate Raw Packet Socket (with undefined header and protocol)
        s = socket.socket(socket.AF_PACKET,
                          socket.SOCK_RAW,
                          socket.ntohs(ETH_P_ALL))
        return s

    except socket.error, msg:
        log.error('Socket could not be created. Error Code : %s' % msg[0])
        log.error(' Message %s' % msg[1])
        raise EnvironmentError('Socket could not be created.')


def parse_packet_header(packet):
    # http://www.infocellar.com/networks/ethernet/frame.htm
    # IEEE 802.3 (LLC)
    # https://docs.python.org/2/library/struct.html#format-characters
    #    packet with bytes 13-14 less than 0x600 are IEEE 802.3
    #    packets with bytes 13-14 equal or greater than 0x600 are Ethernet II.
    if isinstance(packet, tuple):
        packet_data, packet_sender = packet
    mac_header = packet_data[:14]  # first 14 bytes
    # !	network (= big-endian)	standard	none
    # s	char[]	string
    # H	unsigned short	integer	2	(3)
    fmt = '!6s6sH'  # 6 byte string, 6 byte string, unsigned short (2 bytes)
    eth = unpack(fmt, mac_header)

    dest_mac = eth_addr(eth[0])  # 6 bytes
    src_mac = eth_addr(eth[1])  # 6 bytes
    eth_protocol = socket.ntohs(eth[2])  # 2 bytes

    return (dest_mac, src_mac, eth_protocol)

# Pause
raw_input('Press Enter to Begin')

# Address Family : AF_INET (this is IP version 4 or IPv4)
# Type : SOCK_STREAM (this means connection oriented TCP protocol)

# create a AF_PACKET type raw socket (thats basically packet level)
ETH_P_ALL = 0x0003          # Every packet (be careful!!!) */

# Convert 16-bit positive integers from network to host byte order.
# Ceate Raw Packet Socket (with undefined header and protocol)
s = get_virgin_socket()

ip_protocols = get_ip_protocols()

# A data packet on an Ethernet link is called an Ethernet packet, which
# transports an Ethernet frame as its payload
while s is not None:
    time.sleep(WAIT_INTERVAL)

    # Receive data from the socket.
    # The return value is a pair (string, address) where string is a string
    # representing the data received and address is the address of the socket
    # sending the data. See the Unix manual page recv(2) for the meaning of
    # the optional argument flags; it defaults to zero. (The format of
    # address depends on the address family.
    buffer_size = 65565
    packet = s.recvfrom(buffer_size)

    dest_mac, src_mac, eth_protocol = parse_packet_header(packet)
    # packet string from tuple
    packet, packet_addr = packet

    # parse ethernet header
    eth_length = 14

    try:
        print(' Destination MAC : %s' % dest_mac)
        # print(' Source MAC : ' % src_mac)
    except Exception as exc:
        print('Error: %s' % str(exc))
    #print(' Protocol :  %s' % str(eth_protocol))

    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8:
        # Parse IP header
        # take first 20 characters for the ip header

        #    The IPv4 packet header consists of 14 fields, of which 13 are
        #    required. The 14th field is optional and aptly named: options.
        #    The fields in the header are packed with the most significant
        #    byte first (big endian), and for the diagram and discussion,
        #    the most significant bits are considered to come first (MSB 0 bit
        #    numbering). The most significant bit is numbered 0, so the
        #    version field is actually found in the four most significant bits
        #    of the first byte, for example.
        ip_header = packet[eth_length:20 + eth_length]
        fmt = '!BBHHHBBH4s4s'
        iph = unpack(fmt, ip_header)

        # Version
        version_ihl = iph[0]
        version = version_ihl >> 4  # bitwise shift
        # Internet Header Length (IHL)
        ihl = version_ihl & 0xF  # bitwise AND

        # Differentiated Services Code Point (DSCP)
        # Explicit Congestion Notification (ECN)
        # Total Length
        iph_length = ihl * 4
        # Identification
        # Flags
        # Fragment Offset
        # Time To Live (TTL)
        ttl = iph[5]
        # Protocol
        protocol = iph[6]
        # Header Checksum
        # Source address
        s_addr = socket.inet_ntoa(iph[8])
        # Destination address
        d_addr = socket.inet_ntoa(iph[9])
        # Options
        # IP Version, e.g. IPv4





        # TTL: Number of Network Hops


        # Transport Protocol



        # print(' EGP')
        # print 'Version : ' + str(version)
        # print ' IP Header Length : ' + str(ihl)
        print ' TTL : ' + str(ttl)
        print ' Protocol : ' + ip_protocols[protocol]
        print ' Source Address : ' + str(s_addr)
        try:
            print('                  %s' %
                  socket.gethostbyaddr(str(s_addr))[0])
        except:
            pass

        print ' Destination Address : ' + str(d_addr)
        try:
            print('                       %s' %
                  socket.gethostbyaddr(str(d_addr))[0])
            # print socket.gethostbyaddr(str(s_addr))
            # print socket.gethostbyaddr(str(d_addr))
        except:
            pass
        print(' ')

        # TCP protocol
        if protocol == 6:
            t = iph_length + eth_length
            tcp_header = packet[t:t + 20]

            # now unpack them :)
            tcph = unpack('!HHLLBBHHH', tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4

            print ' TCP'
            print ' Source Port : ' + str(source_port)
            print ' Dest Port : ' + str(dest_port)
            print ' Sequence Number : ' + str(sequence)
            print ' Acknowledgement : ' + str(acknowledgement)
            print ' TCP header length : ' + str(tcph_length)
            print(' ')
            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]

            # print 'Data : ' + data

        # ICMP Packets
        elif protocol == 1:
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u + 4]

            # now unpack them :)
            icmph = unpack('!BBH', icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            print(' ICMP')
            print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
            print(' ')

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]

            # print 'Data : ' + data

        # UDP packets
        elif protocol == 17:
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u + 8]

            # now unpack them :)
            udph = unpack('!HHHH', udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print ' UDP'
            print ' Source Port : ' + str(source_port)
            print ' Dest Port : ' + str(dest_port)
            print ' Length : ' + str(length)
            print ' Checksum : ' + str(checksum)
            print(' ')

            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]

            #print 'Data : ' + data

        # some other IP packet like IGMP
        else:
            print 'Protocol other than TCP/UDP/ICMP'

        print('--------------------------------------')
        print
