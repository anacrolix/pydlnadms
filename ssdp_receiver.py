#!/usr/bin/env python3

from socket_wrapper import SocketWrapper
from constant import *
import socket

class SSDPReceiver(SocketWrapper):

    def __init__(self, master):
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
