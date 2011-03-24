from .constant import *
import logging # deleted at end of module
import socket

BODY_SEPARATOR = b'\r\n' * 2

def http_message(first_line, headers, body):
    return (first_line + '\r\n' + httpify_headers(headers) + '\r\n').encode('utf-8') + body


class Message:

    def __init__(self, first_line, headers, body):
        self.first_line = first_line
        self.headers = headers
        self.body = body

    def to_bytes(self):
        return (
            self.first_line + '\r\n' +
            httpify_headers(self.headers) + '\r\n'
        ).encode('utf-8') + self.body


class Request:

    __slots__ = 'method', 'path', 'protocol', 'headers', 'body'

    def __init__(self, method, path, headers=None, body=b''):
        self.method = method
        self.headers = headers or {}
        self.path = path
        self.body = body

    def __setitem__(self, key, value):
        self.headers[key.upper()] = value.strip()

    def __getitem__(self, key):
        return self.headers[key.upper()]

    def __contains__(self, key):
        return key.upper() in self.headers

    def to_bytes(self):
        return Message(
            ' '.join((self.method, self.path, 'HTTP/1.1')),
            self.headers,
            self.body).to_bytes()

    @classmethod
    def from_bytes(cls, buf):
        lines = (a.decode('utf-8') for a in buf.split(b'\r\n'))
        method, path, protocol = lines.__next__().split()
        if protocol != 'HTTP/1.1':
            logger.warning('Untested protocol in HTTP request: %r', protocol)
        from urllib.parse import unquote
        path = unquote(path)
        request = cls(method, path)
        for h in lines:
            if h:
                name, value = h.split(':', 1)
                request[name] = value
        return request


class Response:

    from http.client import responses

    def __init__(self, headers=None, body=b'', code=None, reason=None):
        self.headers = dict(headers) or {}
        self.body = body
        self.code = code
        self.reason = reason

    def to_bytes(self):
        return Message(
            'HTTP/1.1 {:03d} {}'.format(
                self.code,
                self.reason or self.responses[self.code]),
            self.headers.items(),
            self.body).to_bytes()


def httpify_headers(headers):
    from itertools import chain
    def lines():
        for key, value in headers:
            assert key, key
            yield ':'.join([key, ' '+value if value else value])
    return '\r\n'.join(chain(lines(), ['']))

def rfc1123_date():
    import time
    return time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())


class RequestHandlerContext: pass


class Connection:

    __slots__ = 'pollmap', 'buffer', 'dms', 'handler', '_socket'

    logger = logging.getLogger('http')

    def __init__(self, socket, dms, pollmap):
        self.pollmap = pollmap
        self.buffer = b''
        self.dms = dms
        self.handler = None
        self._socket = socket

    def close(self):
        assert self.handler is None, self.handler
        self._socket.close()
        self.pollmap.remove(self)

    def fileno(self):
        return self._socket.fileno()

    def need_read(self):
        return self.handler is None or self.handler.need_read()

    def need_write(self):
        return self.handler is not None and self.handler.need_write()

    def do_write(self):
        try:
            self.handler.do_write()
        except socket.error as exc:
            import errno
            if exc.errno not in [errno.ENOTCONN, errno.EPIPE]:
                raise
            self.logger.exception('Error during handler write')
            self.handler_done(close=True)

    def handler_done(self, close=False):
        assert self.handler is not None, self.handler
        self.handler = None
        if close:
            self.close()

    def do_read(self):
        if self.handler is None:
            ## determine bufsize so that body is left in the socket
            peek_data = self._socket.recv(0x1000, socket.MSG_PEEK)
            index = (self.buffer + peek_data).find(BODY_SEPARATOR)
            assert index >= -1, index
            if index == -1:
                bufsize = len(peek_data)
            else:
                bufsize = index - len(self.buffer) + len(BODY_SEPARATOR)
            assert bufsize <= len(peek_data), (bufsize, len(peek_data))

            data = self._socket.recv(bufsize)
            assert data == peek_data[:bufsize], (data, peek_data)
            if not data:
                self.close()
                return
            self.buffer += data
            del data, bufsize, peek_data

            # complete header hasn't arrived yet
            if index == -1:
                return
            del index

            request = Request.from_bytes(self.buffer)
            self.logger.debug('Received HTTP request: %s', request)
            self.buffer = b''
            factory = self.handler_factory_new(request)
            if factory is None:
                self.close()
                return
            context = RequestHandlerContext()
            context.socket = self._socket
            context.on_done = self.handler_done
            context.request = request
            context.dms = self.dms
            self.handler = factory(context=context)
        else:
            self.handler.do_read()

    def handler_factory_new(self, request):
        '''Returns None if the request cannot be handled. Otherwise returns a callable that takes a request context.'''
        from . import request_handlers
        def send_buffer(buf):
            return functools.partial(request_handlers.SendBuffer, buf)
        def soap_action():
            return request_handlers.Soap
        def send_description(desc):
            import functools
            return functools.partial(
                request_handlers.SendBuffer,
                buffer=Response([
                        ('CONTENT-LENGTH', str(len(desc))),
                        ('CONTENT-TYPE', 'text/xml'),
                        ('DATE', rfc1123_date())
                    ], desc, code=200).to_bytes())
        def send_error(code):
            return send_buffer(http_response(code=code))
        if request.method in ['GET']:
            if request.path == ROOT_DESC_PATH:
                return send_description(self.dms.device_desc)
            for service in SERVICE_LIST:
                if request.path == service.SCPDURL:
                    return send_description(service.xmlDescription)
            if request.path.startswith(RESOURCE_PATH):
                return request_handlers.Resource
        elif request.method in ['POST']:
            if request.path in (
                    service.controlURL for service in SERVICE_LIST):
                return soap_action()
            return None
        elif request.method in ['SUBSCRIBE']:
            return None
        assert False, (request.method, request.path)

    def __repr__(self):
        return '<{} handler={}, buffer={!r}>'.format(
            self.__class__.__name__,
            self.handler,
            self.buffer,)


class Server:

    logger = logging.getLogger('http.server')

    def __init__(self, port, master):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        # TODO allow binding to specific interfaces
        while True:
            try:
                self.socket.bind(('', port))
            except socket.error as exc:
                if exc.errno != 98:
                    raise
            else:
                self.logger.info(
                    'HTTP server listening on %s',
                    self.socket.getsockname())
                break
            port += 1
        # TODO use the socket backlog default
        self.socket.listen(5)
        self.master = master

    def need_read(self):
        return True

    def need_write(self):
        return False

    def fileno(self):
        return self.socket.fileno()

    def do_read(self):
        sock, addr = self.socket.accept()
        self.logger.debug('Accepted connection from %s', addr)
        self.master.on_server_accept(sock)


del logging
