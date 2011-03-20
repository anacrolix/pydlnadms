import logging
from .constant import *
from . import http


class SSDP:

    logger = logging.getLogger('ssdp')

    def __init__(self, dms):
        self.receiver = SSDPReceiver(self)
        self.dms = dms

    @property
    def channels(self):
        return [self.receiver]

    @property
    def notify_interfaces(self):
        from getifaddrs import getifaddrs, IFF_LOOPBACK
        from socket import AF_INET
        for ifaddr in getifaddrs():
            if ifaddr.family == AF_INET and not ifaddr.flags & IFF_LOOPBACK:
                yield ifaddr.family, ifaddr.addr

    def ssdp_multicast(self, family, addr, buf):
        from socket import socket, SOCK_DGRAM, IPPROTO_IP, IP_MULTICAST_LOOP
        s = socket(family, SOCK_DGRAM)
        s.setsockopt(IPPROTO_IP, IP_MULTICAST_LOOP, False)
        s.bind((addr[0], 0))
        s = SocketWrapper(s)
        s.sendto(buf, (SSDP_MCAST_ADDR, SSDP_PORT))

    def send_goodbye(self):
        for nt in self.dms.all_targets:
            for family, addr in self.notify_interfaces:
                buf = http.Request('NOTIFY', '*', (
                    ('HOST', '{}:{:d}'.format(SSDP_MCAST_ADDR, SSDP_PORT)),
                    ('NT', nt),
                    ('USN', self.dms.usn_from_target(nt)),
                    ('NTS', 'ssdp:byebye'),)).to_bytes()
                self.ssdp_multicast(family, addr, buf)
        self.logger.debug('Sent SSDP byebye notifications')

    def send_notify(self):
        # TODO for each interface
        # sends should also be delayed 100ms by eventing
        for nt in self.dms.all_targets:
            for family, addr in self.notify_interfaces:
                buf = http.Request('NOTIFY', '*', [
                    ('HOST', '{}:{:d}'.format(SSDP_MCAST_ADDR, SSDP_PORT)),
                    ('CACHE-CONTROL', 'max-age={:d}'.format(
                        self.dms.notify_interval * 2 + EXPIRY_FUDGE)),
                    ('LOCATION', 'http://{}:{:d}{}'.format(
                        addr[0],
                        self.http_address[1],
                        ROOT_DESC_PATH)),
                    ('NT', nt),
                    ('NTS', 'ssdp:alive'),
                    ('SERVER', SERVER_FIELD),
                    ('USN', self.usn_from_target(nt))]).to_bytes()
                self.ssdp_multicast(family, addr, buf)
        self.logger.debug('Sent SSDP alive notifications')

    def process_request(self, data, peeraddr, sockaddr):
        request = http.Request.from_bytes(data)
        if request.method != 'M-SEARCH':
            return
        st = request['st']
        if st in self.dms.all_targets:
            sts = [st]
        elif st == 'ssdp:all':
            sts = self.dms.all_targets
        else:
            self.logger.debug('Ignoring M-SEARCH for %r', st)
            return
        for st in sts:
            self.send_msearch_reply(sockaddr, peeraddr, st)

    @property
    def http_address(self):
        return self.dms.http_server.socket.getsockname()

    @property
    def usn_from_target(self):
        return self.dms.usn_from_target

    @property
    def max_age(self):
        return self.dms.notify_interval * 2 + EXPIRY_FUDGE

    def send_msearch_reply(self, sockaddr, peeraddr, st):
        buf = http.Response([
                ('CACHE-CONTROL', 'max-age={:d}'.format(self.max_age)),
                ('DATE', http.rfc1123_date()),
                ('EXT', ''),
                ('LOCATION', 'http://{}:{:d}{}'.format(
                    sockaddr[0],
                    self.http_address[1],
                    ROOT_DESC_PATH)),
                ('SERVER', SERVER_FIELD),
                ('ST', st),
                ('USN', self.usn_from_target(st))
            ], code=200
        ).to_bytes()
        self.receiver.sendto(buf, peeraddr)
        self.logger.debug('Responded to M-SEARCH from %s', peeraddr)


from .socket_wrapper import SocketWrapper

class SSDPReceiver(SocketWrapper):

    def __init__(self, master):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        s.bind(('', SSDP_PORT))
        import struct
        mreqn = struct.pack(
            '4s4si',
            socket.inet_aton(SSDP_MCAST_ADDR),
            socket.inet_aton('0.0.0.0'),
            0)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreqn)
        super().__init__(s)
        self.master = master

    def need_read(self):
        return True

    def need_write(self):
        return False

    def do_read(self):
        # MTU should limit UDP packet sizes to well below this
        data, addr = self.recvfrom(0x1000)
        assert len(data) < 0x1000, len(addr)
        self.master.process_request(data, addr, self.getsockname())


if __name__ == '__main__':
    class Master:
        def process_request(self, buf, peeraddr, sockaddr):
            print(buf, peeraddr, sockaddr)
    master = Master()
    sr = SSDPReceiver(master)
    while True:
        sr.do_read()

del logging
