#!/usr/bin/env python3

from ctypes import (
    Structure, Union, POINTER,
    pointer, get_errno, cast,
    c_ushort, c_char, c_byte, c_void_p, c_char_p, c_uint, c_int, c_uint16, c_uint32
)
import ctypes.util
import ctypes
import collections
import pdb

IFF_LOOPBACK = 0x8

#struct sockaddr
  #{
    #__SOCKADDR_COMMON (sa_);	/* Common data: address family and length.  */
    #char sa_data[14];		/* Address data.  */
  #};

sa_family_t = c_ushort

class struct_sockaddr(Structure):

    _fields_ = [
        ('sa_family', c_ushort),
        ('sa_data', c_byte * 14),]

#/* Structure describing an Internet (IP) socket address. */
##define __SOCK_SIZE__	16		/* sizeof(struct sockaddr)	*/
#struct sockaddr_in {
  #sa_family_t		sin_family;	/* Address family		*/
  #__be16		sin_port;	/* Port number			*/
  #struct in_addr	sin_addr;	/* Internet address		*/

  #/* Pad to size of `struct sockaddr'. */
  #unsigned char		__pad[__SOCK_SIZE__ - sizeof(short int) -
			#sizeof(unsigned short int) - sizeof(struct in_addr)];
#};
##define sin_zero	__pad		/* for BSD UNIX comp. -FvK	*/

struct_in_addr = c_byte * 4

class struct_sockaddr_in(Structure):

    _fields_ = [
        ('sin_family', sa_family_t),
        ('sin_port', c_uint16),
        ('sin_addr', struct_in_addr)]

#struct in6_addr
#{
	#union
	#{
		#__u8		u6_addr8[16];
		#__be16		u6_addr16[8];
		#__be32		u6_addr32[4];
	#} in6_u;
##define s6_addr			in6_u.u6_addr8
##define s6_addr16		in6_u.u6_addr16
##define s6_addr32		in6_u.u6_addr32
#};

struct_in6_addr = c_byte * 16

#/* IPv6 Wildcard Address (::) and Loopback Address (::1) defined in RFC2553
 #* NOTE: Be aware the IN6ADDR_* constants and in6addr_* externals are defined
 #* in network byte order, not in host byte order as are the IPv4 equivalents
 #*/

#struct sockaddr_in6 {
	#unsigned short int	sin6_family;    /* AF_INET6 */
	#__be16			sin6_port;      /* Transport layer port # */
	#__be32			sin6_flowinfo;  /* IPv6 flow information */
	#struct in6_addr		sin6_addr;      /* IPv6 address */
	#__u32			sin6_scope_id;  /* scope id (new in RFC2553) */
#};

class struct_sockaddr_in6(Structure):

    _fields_ = [
        ('sin6_family', c_ushort),
        ('sin6_port', c_uint16),
        ('sin6_flowinfo', c_uint32),
        ('sin6_addr', struct_in6_addr),
        ('sin6_scope_id', c_uint32)]

#struct ifaddrs
#{
  #struct ifaddrs *ifa_next;	/* Pointer to the next structure.  */

  #char *ifa_name;		/* Name of this network interface.  */
  #unsigned int ifa_flags;	/* Flags as from SIOCGIFFLAGS ioctl.  */

  #struct sockaddr *ifa_addr;	/* Network address of this interface.  */
  #struct sockaddr *ifa_netmask; /* Netmask of this interface.  */
  #union
  #{
    #/* At most one of the following two is valid.  If the IFF_BROADCAST
       #bit is set in `ifa_flags', then `ifa_broadaddr' is valid.  If the
       #IFF_POINTOPOINT bit is set, then `ifa_dstaddr' is valid.
       #It is never the case that both these bits are set at once.  */
    #struct sockaddr *ifu_broadaddr; /* Broadcast address of this interface. */
    #struct sockaddr *ifu_dstaddr; /* Point-to-point destination address.  */
  #} ifa_ifu;
  #/* These very same macros are defined by <net/if.h> for `struct ifaddr'.
     #So if they are defined already, the existing definitions will be fine.  */
## ifndef ifa_broadaddr
##  define ifa_broadaddr	ifa_ifu.ifu_broadaddr
## endif
## ifndef ifa_dstaddr
##  define ifa_dstaddr	ifa_ifu.ifu_dstaddr
## endif

  #void *ifa_data;		/* Address-specific data (may be unused).  */
#};

class union_ifa_ifu(Union):

    _fields_ = [
        ('ifu_broadaddr', POINTER(struct_sockaddr)),
        ('ifu_dstaddr', POINTER(struct_sockaddr)),]

class struct_ifaddrs(Structure):
    pass

struct_ifaddrs._fields_ = [
    ('ifa_next', POINTER(struct_ifaddrs)),
    ('ifa_name', c_char_p),
    ('ifa_flags', c_uint),
    ('ifa_addr', POINTER(struct_sockaddr)),
    ('ifa_netmask', POINTER(struct_sockaddr)),
    #('ifa_ifu', union_ifa_ifu),
    ('ifa_data', c_void_p),]

py_ifaddrs = collections.namedtuple('py_ifaddrs', [
    'name',
    'flags',
    'family',
    'addr',
    'netmask'])

class py_ifaddrs:

    __slots__ = 'name', 'flags', 'family', 'addr', 'netmask'

    def __init__(self, **kwds):
        for key, value in kwds.items():
            setattr(self, key, value)

    def __repr__(self):
        s = self.__class__.__name__ + '('
        kwargs = {slot: getattr(self, slot) for slot in self.__slots__}
        kwargs['flags'] = hex(kwargs['flags'])
        s += ', '.join('{}={}'.format(k, v) for k, v in kwargs.items())
        return s + ')'

class struct_in_pktinfo(Structure):

    _fields_ = [
        ('ipi_ifindex', ctypes.c_uint),
        ('ipi_spec_dst', struct_in_addr),
        ('ipi_addr', struct_in_addr)]


libc = ctypes.CDLL(ctypes.util.find_library('c'))
_getifaddrs = libc.getifaddrs
_getifaddrs.restype = c_int
_getifaddrs.argtypes = [POINTER(POINTER(struct_ifaddrs))]
_freeifaddrs = libc.freeifaddrs
_freeifaddrs.restype = None
_freeifaddrs.argtypes = [POINTER(struct_ifaddrs)]

def ifap_iter(ifap):
    ifa = ifap.contents
    while True:
        yield ifa
        if not ifa.ifa_next:
            break
        ifa = ifa.ifa_next.contents

class uniquedict(dict):

    def __setitem__(self, key, value):
        if key in self:
            raise KeyError('Key {!r} already set'.format(key))
        else:
            super().__setitem__(key, value)

def pythonize_sockaddr(sa):
    from socket import AF_INET, AF_INET6, ntohs, ntohl, inet_ntop
    family = sa.sa_family
    if family == AF_INET:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in)).contents
        addr = (
            inet_ntop(family, sa.sin_addr),
            ntohs(sa.sin_port))
    elif family == AF_INET6:
        sa = cast(pointer(sa), POINTER(struct_sockaddr_in6)).contents
        addr = (
            inet_ntop(family, sa.sin6_addr),
            ntohs(sa.sin6_port),
            ntohl(sa.sin6_flowinfo),
            sa.sin6_scope_id)
    else:
        addr = None
    return family, addr

def getifaddrs():
    ifap = POINTER(struct_ifaddrs)()
    result = _getifaddrs(pointer(ifap))
    if result == -1:
        raise OSError(get_errno())
    elif result == 0:
        pass
    else:
        assert False, result
    del result
    try:
        retval = []
        for ifa in ifap_iter(ifap):
            family, addr = pythonize_sockaddr(ifa.ifa_addr.contents)
            retval.append(py_ifaddrs(
                name=ifa.ifa_name,
                family=family,
                flags=ifa.ifa_flags,
                addr=addr,
                netmask=ifa.ifa_netmask,))
        return retval
    finally:
        _freeifaddrs(ifap)

if __name__ == '__main__':
    from pprint import pprint
    pprint(getifaddrs())
