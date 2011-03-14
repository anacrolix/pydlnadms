import logging
import socket

class SocketWrapper:

    def __init__(self, socket_):
        self.__socket = socket_
        self.__closed = False
        try:
            self.peername = self.__socket.getpeername()
        except socket.error as exc:
            from errno import ENOTCONN
            if exc.errno in [ENOTCONN]:
                self.peername = None
            else:
                raise
        self.sockname = self.__socket.getsockname()

    def getsockname(self):
        return self.__socket.getsockname()

    def send(self, data):
        sockname = self.__socket.getsockname()
        peername = self.__socket.getpeername()
        sent = self.__socket.send(data)
        fmt = 'Sent %s bytes on %s to %s'
        args = [sent, sockname, peername]
        if sent <= 24 * 80:
            fmt += ': %r'
            args += [data[:sent]]
        logging.debug(fmt, *args)
        return sent

    def sendto(self, buf, addr):
        sent = self.__socket.sendto(buf, addr)
        logging.debug('Sent %s bytes from %s to %s: %r', sent,
            self.__socket.getsockname(), addr, buf[:sent])
        return sent

    def recv(self, bufsize, flags=0):
        data = self.__socket.recv(bufsize, flags)
        from socket import MSG_PEEK
        if flags & MSG_PEEK:
            logging.debug('Peeked at %s bytes', len(data))
        else:
            logging.debug('Received %s bytes on %s%s: %r',
                len(data),
                self.__socket.getsockname(),
                self.peername,
                data)
        return data

    def recvfrom(self, *args, **kwds):
        buf, addr = self.__socket.recvfrom(*args, **kwds)
        logging.debug('Received %s bytes on %s%s: %r',
            len(buf), self.sockname, addr, buf)
        return buf, addr

    def fileno(self):
        return self.__socket.fileno()

    def close(self):
        assert not self.__closed
        self.__socket.close()
        logging.debug('Closed socket: %s', self)
        self.__closed = True

    def __repr__(self):
        return '<SocketWrapper sock={} peer={}>'.format(
            self.sockname,
            self.peername,)
