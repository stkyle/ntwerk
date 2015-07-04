# -*- coding: utf-8 -*-
"""
Created on Thu Jul  2 19:21:21 2015

http://man7.org/linux/man-pages/man7/netdevice.7.html
http://www.microhowto.info/howto/get_the_ip_address_of_a_network_interface_in_c_using_siocgifaddr.html



man7.org > Linux > man-pages
Linux/UNIX system programming training
NAME | SYNOPSIS | DESCRIPTION | NOTES | BUGS | SEE ALSO | COLOPHON
  
NETDEVICE(7)              Linux Programmer's Manual             NETDEVICE(7)
NAME         top

       netdevice - low-level access to Linux network devices
SYNOPSIS         top

       #include <sys/ioctl.h>
       #include <net/if.h>
DESCRIPTION         top

       This man page describes the sockets interface which is used to
       configure network devices.

       Linux supports some standard ioctls to configure network devices.
       They can be used on any socket's file descriptor regardless of the
       family or type.  Most of them pass an ifreq structure:

           struct ifreq {
               char ifr_name[IFNAMSIZ]; /* Interface name */
               union {
                   struct sockaddr ifr_addr;
                   struct sockaddr ifr_dstaddr;
                   struct sockaddr ifr_broadaddr;
                   struct sockaddr ifr_netmask;
                   struct sockaddr ifr_hwaddr;
                   short           ifr_flags;
                   int             ifr_ifindex;
                   int             ifr_metric;
                   int             ifr_mtu;
                   struct ifmap    ifr_map;
                   char            ifr_slave[IFNAMSIZ];
                   char            ifr_newname[IFNAMSIZ];
                   char           *ifr_data;
               };
           };

       Normally, the user specifies which device to affect by setting
       ifr_name to the name of the interface.  All other members of the
       structure may share memory.

   Ioctls
       If an ioctl is marked as privileged, then using it requires an
       effective user ID of 0 or the CAP_NET_ADMIN capability.  If this is
       not the case, EPERM will be returned.

       SIOCGIFNAME
              Given the ifr_ifindex, return the name of the interface in
              ifr_name.  This is the only ioctl which returns its result in
              ifr_name.

       SIOCGIFINDEX
              Retrieve the interface index of the interface into
              ifr_ifindex.

       SIOCGIFFLAGS, SIOCSIFFLAGS
              Get or set the active flag word of the device.  ifr_flags
              contains a bit mask of the following values:

                                      Device flags
              IFF_UP            Interface is running.
              IFF_BROADCAST     Valid broadcast address set.
              IFF_DEBUG         Internal debugging flag.
              IFF_LOOPBACK      Interface is a loopback interface.

              IFF_POINTOPOINT   Interface is a point-to-point link.
              IFF_RUNNING       Resources allocated.
              IFF_NOARP         No arp protocol, L2 destination address not
                                set.
              IFF_PROMISC       Interface is in promiscuous mode.
              IFF_NOTRAILERS    Avoid use of trailers.
              IFF_ALLMULTI      Receive all multicast packets.
              IFF_MASTER        Master of a load balancing bundle.
              IFF_SLAVE         Slave of a load balancing bundle.
              IFF_MULTICAST     Supports multicast
              IFF_PORTSEL       Is able to select media type via ifmap.
              IFF_AUTOMEDIA     Auto media selection active.
              IFF_DYNAMIC       The addresses are lost when the interface
                                goes down.
              IFF_LOWER_UP      Driver signals L1 up (since Linux 2.6.17)
              IFF_DORMANT       Driver signals dormant (since Linux 2.6.17)
              IFF_ECHO          Echo sent packets (since Linux 2.6.25)

              Setting the active flag word is a  privileged  operation,  but
              any process may read it.

       SIOCGIFPFLAGS, SIOCSIFPFLAGS
              Get or set extended (private) flags for the device.  ifr_flags
              contains a bit mask of the following values:

                                      Private flags
              IFF_802_1Q_VLAN      Interface is 802.1Q VLAN device.
              IFF_EBRIDGE          Interface is Ethernet bridging device.
              IFF_SLAVE_INACTIVE   Interface is inactive bonding slave.
              IFF_MASTER_8023AD    Interface is 802.3ad bonding master.
              IFF_MASTER_ALB       Interface is balanced-alb bonding master.
              IFF_BONDING          Interface is a bonding master or slave.
              IFF_SLAVE_NEEDARP    Interface needs ARPs for validation.
              IFF_ISATAP           Interface is RFC4214 ISATAP interface.

              Setting the extended (private) interface flags is a privileged
              operation.

       SIOCGIFADDR, SIOCSIFADDR
              Get  or set the address of the device using ifr_addr.  Setting
              the  interface  address  is  a  privileged   operation.    For
              compatibility,   only   AF_INET   addresses  are  accepted  or
              returned.

       SIOCGIFDSTADDR, SIOCSIFDSTADDR
              Get or set the destination address of a point-to-point  device
              using  ifr_dstaddr.  For compatibility, only AF_INET addresses
              are accepted or returned.  Setting the destination address  is
              a privileged operation.

       SIOCGIFBRDADDR, SIOCSIFBRDADDR
              Get   or   set  the  broadcast  address  for  a  device  using
              ifr_brdaddr.  For compatibility, only  AF_INET  addresses  are
              accepted  or  returned.   Setting  the  broadcast address is a
              privileged operation.

       SIOCGIFNETMASK, SIOCSIFNETMASK
              Get or set the network mask for a  device  using  ifr_netmask.
              For  compatibility,  only  AF_INET  addresses  are accepted or
              returned.  Setting the network mask is a privileged operation.

       SIOCGIFMETRIC, SIOCSIFMETRIC
              Get or set the metric of the device using ifr_metric.  This is
              currently  not  implemented;  it  sets  ifr_metric to 0 if you
              attempt to read it and returns EOPNOTSUPP if  you  attempt  to
              set it.

       SIOCGIFMTU, SIOCSIFMTU
              Get  or  set the MTU (Maximum Transfer Unit) of a device using
              ifr_mtu.  Setting the MTU is a privileged operation.   Setting
              the MTU to too small values may cause kernel crashes.

       SIOCGIFHWADDR, SIOCSIFHWADDR
              Get  or set the hardware address of a device using ifr_hwaddr.
              The hardware  address  is  specified  in  a  struct  sockaddr.
              sa_family  contains  the  ARPHRD_* device type, sa_data the L2
              hardware address starting from byte 0.  Setting  the  hardware
              address is a privileged operation.

       SIOCSIFHWBROADCAST
              Set   the   hardware   broadcast  address  of  a  device  from
              ifr_hwaddr.  This is a privileged operation.

       SIOCGIFMAP, SIOCSIFMAP
              Get or set the interface's hardware parameters using  ifr_map.
              Setting the parameters is a privileged operation.

                  struct ifmap {
                      unsigned long   mem_start;
                      unsigned long   mem_end;
                      unsigned short  base_addr;
                      unsigned char   irq;
                      unsigned char   dma;
                      unsigned char   port;
                  };

              The  interpretation  of  the  ifmap  structure  depends on the
              device driver and the architecture.

       SIOCADDMULTI, SIOCDELMULTI
              Add an address to or delete an address from the device's  link
              layer   multicast   filters   using   ifr_hwaddr.   These  are
              privileged operations.  See also packet(7) for an alternative.

       SIOCGIFTXQLEN, SIOCSIFTXQLEN
              Get or set  the  transmit  queue  length  of  a  device  using
              ifr_qlen.   Setting  the transmit queue length is a privileged
              operation.

       SIOCSIFNAME
              Changes the name of the interface  specified  in  ifr_name  to
              ifr_newname.   This  is a privileged operation.  It is allowed
              only when the interface is not up.

       SIOCGIFCONF
              Return a list of interface (transport layer) addresses.   This
              currently  means  only  addresses of the AF_INET (IPv4) family
              for compatibility.  Unlike the others, this  ioctl  passes  an
              ifconf structure:

                  struct ifconf {
                      int                 ifc_len; /* size of buffer */
                      union {
                          char           *ifc_buf; /* buffer address */
                          struct ifreq   *ifc_req; /* array of structures */
                      };
                  };

              If  ifc_req  is NULL, SIOCGIFCONF returns the necessary buffer
              size  in  bytes  for  receiving  all  available  addresses  in
              ifc_len.  Otherwise, ifc_req contains a pointer to an array of
              ifreq structures to be filled with  all  currently  active  L3
              interface  addresses.   ifc_len contains the size of the array
              in bytes.  Within each ifreq structure, ifr_name will  receive
              the  interface  name,  and  ifr_addr  the address.  The actual
              number of bytes transferred is returned in ifc_len.

              If the size specified by ifc_len is insufficient to store  all
              the  addresses,  the  kernel  will skip the exceeding ones and
              return success.  There is no reliable way  of  detecting  this
              condition  once  it has occurred.  It is therefore recommended
              to either determine the necessary buffer  size  beforehand  by
              calling  SIOCGIFCONF with ifc_req set to NULL, or to retry the
              call with a bigger buffer whenever ifc_len upon return differs
              by less than sizeof(struct ifreq) from its original value.

              If  an  error occurs accessing the ifconf or ifreq structures,
              EFAULT will be returned.

       Most protocols  support  their  own  ioctls  to  configure  protocol-
       specific  interface  options.   See  the  protocol  man  pages  for a
       description.  For configuring IP addresses, see ip(7).

       In addition, some devices support  private  ioctls.   These  are  not
       described here.
NOTES         top

       Strictly speaking, SIOCGIFCONF and the other ioctls that accept or
       return only AF_INET socket addresses, are IP-specific and belong in
       ip(7).

       The names of interfaces with no addresses or that don't have the
       IFF_RUNNING flag set can be found via /proc/net/dev.

       Local IPv6 IP addresses can be found via /proc/net or via
       rtnetlink(7).
BUGS         top

       glibc 2.1 is missing the ifr_newname macro in <net/if.h>.  Add the
       following to your program as a workaround:

           #ifndef ifr_newname
           #define ifr_newname     ifr_ifru.ifru_slave
           #endif
SEE ALSO         top

       proc(5), capabilities(7), ip(7), rtnetlink(7)
COLOPHON         top

       This page is part of release 4.00 of the Linux man-pages project.  A
       description of the project, information about reporting bugs, and the
       latest version of this page, can be found at
       http://www.kernel.org/doc/man-pages/.

Linux                            2014-01-24                     NETDEVICE(7)
Copyright and license for this manual page
HTML rendering created 2015-05-07 by Michael Kerrisk, author of The Linux Programming Interface, maintainer of the Linux man-pages project.

For details of in-depth Linux/UNIX system programming training courses that I teach, look here.

Hosting by jambit GmbH.

 Valid XHTML 1.1

Cover of TLPI

 1 #
  2  * INET         An implementation of the TCP/IP protocol suite for the LINUX
  3  *              operating system.  INET is implemented using the  BSD Socket
  4  *              interface as the means of communication with the user level.
  5  *
  6  *              Definitions of the socket-level I/O control calls.
  7  *
  8  * Version:     @(#)sockios.h   1.0.2   03/09/93
  9  *
 10  * Authors:     Ross Biro
 11  *              Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 12  *
 13  *              This program is free software; you can redistribute it and/or
 14  *              modify it under the terms of the GNU General Public License
 15  *              as published by the Free Software Foundation; either version
 16  *              2 of the License, or (at your option) any later version.
 17  */
 18 #ifndef _LINUX_SOCKIOS_H
 19 #define _LINUX_SOCKIOS_H
 20 
 21 #include <asm/sockios.h>
 22 
 23 # Linux-specific socket ioctls */
 24 #define SIOCINQ         FIONREAD
 25 #define SIOCOUTQ        TIOCOUTQ
 26 
 27 # Routing table calls. */
 28 #define SIOCADDRT     = 0x890B          # add routing table entry      */
 29 #define SIOCDELRT     = 0x890C          # delete routing table entry   */
 30 #define SIOCRTMSG     = 0x890D          # call to routing system       */
 31 
"""

# Socket configuration controls. */
# SIOCGIFNAME          # get iface name               */
#  Given the ifr_ifindex, return the name of the interface in
#  ifr_name.  This is the only ioctl which returns its result in
#  ifr_name.
SIOCGIFNAME = 0x8910  



SIOCSIFLINK = 0x8911          # set iface channel            */
SIOCGIFCONF = 0x8912          # get iface list               */
SIOCGIFFLAGS = 0x8913          # get flags                    */
SIOCSIFFLAGS = 0x8914          # set flags                    */

# SIOCGIFADDR, SIOCSIFADDR
#              Get  or set the address of the device using ifr_addr.  Setting
#              the  interface  address  is  a  privileged   operation.    For
#              compatibility,   only   AF_INET   addresses  are  accepted  or
#              returned.
SIOCGIFADDR = 0x8915        # get PA address               */
SIOCSIFADDR = 0x8916        # set PA address               */


SIOCGIFDSTADDR= 0x8917          # get remote PA address        */
SIOCSIFDSTADDR= 0x8918          # set remote PA address        */
SIOCGIFBRDADDR= 0x8919          # get broadcast PA address     */
SIOCSIFBRDADDR= 0x891a          # set broadcast PA address     */
SIOCGIFNETMASK= 0x891b          # get network PA mask          */
SIOCSIFNETMASK= 0x891c          # set network PA mask          */
SIOCGIFMETRIC = 0x891d          # get metric                   */
SIOCSIFMETRIC = 0x891e          # set metric                   */
SIOCGIFMEM    = 0x891f          # get memory address (BSD)     */
SIOCSIFMEM    = 0x8920          # set memory address (BSD)     */
SIOCGIFMTU    = 0x8921          # get MTU size                 */
SIOCSIFMTU    = 0x8922          # set MTU size                 */
SIOCSIFNAME   = 0x8923          # set interface name */
SIOCSIFHWADDR = 0x8924          # set hardware address         */
SIOCGIFENCAP  = 0x8925          # get/set encapsulations       */
SIOCSIFENCAP  = 0x8926          
SIOCGIFHWADDR = 0x8927          # Get hardware address         */
SIOCGIFSLAVE  = 0x8929          # Driver slaving support       */
SIOCSIFSLAVE  = 0x8930
SIOCADDMULTI  = 0x8931          # Multicast address lists      */
SIOCDELMULTI  = 0x8932
# SIOCGIFINDEX
#     Retrieve the interface index of the interface into
#     ifr_ifindex.
SIOCGIFINDEX = 0x8933          # name -> if_index mapping     */
SIOGIFINDEX = SIOCGIFINDEX    # misprint compatibility :-)   */
SIOCSIFPFLAGS = 0x8934          # set/get extended flags set   */
SIOCGIFPFLAGS = 0x8935
SIOCDIFADDR = 0x8936          # delete PA address            */
SIOCSIFHWBROADCAST = 0x8937  # set hardware broadcast addr  */
SIOCGIFCOUNT = 0x8938          # get number of devices */

SIOCGIFBR = 0x8940          # Bridging support             */
SIOCSIFBR = 0x8941          # Set bridging options         */

SIOCGIFTXQLEN = 0x8942          # Get the tx queue length      */
SIOCSIFTXQLEN = 0x8943          # Set the tx queue length      */
 
 # SIOCGIFDIVERT was: = 0x8944          Frame diversion support */
# SIOCSIFDIVERT was: = 0x8945          Set frame diversion options */

SIOCETHTOOL   = 0x8946          # Ethtool interface            */

SIOCGMIIPHY   = 0x8947          # Get address of MII PHY in use. */
SIOCGMIIREG   = 0x8948          # Read MII PHY register.       */
SIOCSMIIREG   = 0x8949          # Write MII PHY register.      */

SIOCWANDEV    = 0x894A          # get/set netdev parameters    */


# ARP cache control calls. */
# Note: 0x8950 - 0x8952  * obsolete calls, don't re-use */
SIOCDARP      = 0x8953          # delete ARP table entry       */
SIOCGARP      = 0x8954          # get ARP table entry          */
SIOCSARP      = 0x8955          # set ARP table entry          */

# RARP cache control calls. */
SIOCDRARP     = 0x8960          # delete RARP table entry      */
SIOCGRARP     = 0x8961          # get RARP table entry         */
SIOCSRARP     = 0x8962          # set RARP table entry         */

# Driver configuration calls */
SIOCGIFMAP    = 0x8970          # Get device parameters        */SIOCSIFMAP    = 0x8971          # Set device parameters        */

# DLCI configuration calls */
SIOCADDDLCI   = 0x8980          # Create new DLCI device       */
SIOCDELDLCI   = 0x8981          # Delete DLCI device           */
SIOCGIFVLAN   = 0x8982          # 802.1Q VLAN support          */
SIOCSIFVLAN   = 0x8983          # Set 802.1Q VLAN options      */

# bonding calls */
SIOCBONDENSLAVE 0x8990          # enslave a device to the bond */
SIOCBONDRELEASE 0x8991          # release a slave from the bond*/
SIOCBONDSETHWADDR    = 0x8992   # set the hw addr of the bond  */
SIOCBONDSLAVEINFOQUERY 0x8993   # rtn info about slave state   */
SIOCBONDINFOQUERY    = 0x8994   # rtn info about bond state    */
SIOCBONDCHANGEACTIVE = 0x8995   # update to a new active slave */

# bridge calls */
SIOCBRADDBR   = 0x89a0          # create new bridge device     */
SIOCBRDELBR   = 0x89a1          # remove bridge device         */
SIOCBRADDIF   = 0x89a2          # add interface to bridge      */
SIOCBRDELIF   = 0x89a3          # remove interface from bridge */

# hardware time stamping: parameters in linux/net_tstamp.h */
SIOCSHWTSTAMP = 0x89b0











# IEEE 802.3 Ethernet magic constants.  The frame sizes omit the preamble
# and FCS/CRC (frame check sequence). 
ETH_ALEN = 6		/* Octets in one ethernet addr	 */
ETH_HLEN=	14		/* Total octets in header.	 */
ETH_ZLEN=	60		/* Min. octets in frame sans FCS */
ETH_DATA_LEN=	1500		/* Max. octets in payload	 */
ETH_FRAME_LEN=	1514		/* Max. octets in frame sans FCS */


# These are the defined Ethernet Protocol ID's.
ETH_P_LOOP=	0x0060		/* Ethernet Loopback packet	*/
ETH_P_PUP=	0x0200		/* Xerox PUP packet		*/
ETH_P_PUPAT=	0x0201		/* Xerox PUP Addr Trans packet	*/
ETH_P_IP=	0x0800		/* Internet Protocol packet	*/
ETH_P_X25=	0x0805		/* CCITT X.25			*/
ETH_P_ARP=	0x0806		/* Address Resolution packet	*/
ETH_P_BPQ=	0x08FF		/* G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_IEEEPUP	0x0a00		/* Xerox IEEE802.3 PUP packet */
#define ETH_P_IEEEPUPAT	0x0a01		/* Xerox IEEE802.3 PUP Addr Trans packet */
#define ETH_P_DEC       0x6000          /* DEC Assigned proto           */
#define ETH_P_DNA_DL    0x6001          /* DEC DNA Dump/Load            */
#define ETH_P_DNA_RC    0x6002          /* DEC DNA Remote Console       */
#define ETH_P_DNA_RT    0x6003          /* DEC DNA Routing              */
#define ETH_P_LAT       0x6004          /* DEC LAT                      */
#define ETH_P_DIAG      0x6005          /* DEC Diagnostics              */
#define ETH_P_CUST      0x6006          /* DEC Customer use             */
#define ETH_P_SCA       0x6007          /* DEC Systems Comms Arch       */
#define ETH_P_RARP      0x8035		/* Reverse Addr Res packet	*/
#define ETH_P_ATALK	0x809B		/* Appletalk DDP		*/
#define ETH_P_AARP	0x80F3		/* Appletalk AARP		*/
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_IPX	0x8137		/* IPX over DIX			*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
#define ETH_P_WCCP	0x883E		/* Web-cache coordination protocol
# * defined in draft-wilson-wrec-wccp-v2-00.txt */
#define ETH_P_PPP_DISC	0x8863		/* PPPoE discovery messages     */
#define ETH_P_PPP_SES	0x8864		/* PPPoE session messages	*/
#define ETH_P_MPLS_UC	0x8847		/* MPLS Unicast traffic		*/
#define ETH_P_MPLS_MC	0x8848		/* MPLS Multicast traffic	*/
#define ETH_P_ATMMPOA	0x884c		/* MultiProtocol Over ATM	*/
#define ETH_P_ATMFATE	0x8884		/* Frame-based ATM Transport
					 * over Ethernet
					 */
#define ETH_P_AOE	0x88A2		/* ATA over Ethernet		*/

# Non DIX types. Won't clash for 1500 types.
#
 
ETH_P_802_3=	0x0001  # Dummy type for 802.3 frames  */
ETH_P_AX25=	0x0002  #  Dummy protocol id for AX.25  */
ETH_P_ALL=	0x0003  # Every packet (be careful!!!) */
ETH_P_802_2=	0x0004  #  802.2 frames 		*/
ETH_P_SNAP=	0x0005  # Internal only		*/
ETH_P_DDCMP   =  0x0006   # DEC DDCMP: Internal only     */
ETH_P_WAN_PPP=   0x0007     #  Dummy type for WAN PPP frames*/
ETH_P_PPP_MP  =  0x0008    # Dummy type for PPP MP frames */
ETH_P_LOCALTALK =0x0009  # Localtalk pseudo type 	*/
ETH_P_PPPTALK=	0x0010	  #  Dummy type for Atalk over PPP*/
ETH_P_TR_802_2=	0x0011	  # 802.2 frames 		*/
ETH_P_MOBITEX=	0x0015	  #  Mobitex (kaz@cafe.net)	*/
ETH_P_CONTROL=	0x0016	  # Card specific control frames */
ETH_P_IRDA=	0x0017	  # Linux-IrDA			*/
ETH_P_ECONET=	0x0018	  #  Acorn Econet			*/
ETH_P_HDLC=	0x0019	  # HDLC frames			*/
ETH_P_ARCNET=	0x001A	  #  1A for ArcNet :-)            */
 
