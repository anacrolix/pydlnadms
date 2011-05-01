#!/usr/bin/env python3
# filetype=python3

import collections
import datetime
import errno
from xml.etree import ElementTree as etree
import fcntl
import http.client
import getpass
import heapq
import logging # deleted at end of module
import os
import os.path
import platform
import pprint
import queue
import random
import select
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from xml.sax.saxutils import escape as xml_escape


logger = logging.getLogger('pydlnadms')


# fix xml.etree.ElementTree.tostring for python < 3.2

_etree_tostring_original = etree.tostring

def _etree_tostring_wrapper(*args, **kwargs):
    if kwargs.get('encoding') == 'unicode':
        del kwargs['encoding']
    return _etree_tostring_original(*args, **kwargs)

if sys.version_info.major <= 3 and sys.version_info.minor < 2:
    etree.tostring = _etree_tostring_wrapper


def pretty_sockaddr(addr):
    assert len(addr) == 2, addr
    return '{}:{:d}'.format(addr[0], addr[1])


EXPIRY_FUDGE = 10
UPNP_ROOT_DEVICE = 'upnp:rootdevice'
UPNP_DOMAIN_NAME = 'schemas-upnp-org'
ROOT_DESC_PATH = '/rootDesc.xml'
SERVER_FIELD = '{}/{} DLNADOC/1.50 UPnP/1.0 PyDLNADMS/1.0'.format(
    *platform.linux_distribution()[0:2])
ROOT_DEVICE_DEVICE_TYPE = 'urn:schemas-upnp-org:device:MediaServer:1'
ROOT_DEVICE_FRIENDLY_NAME = 'pydlnadms: {!r} on {!r}'.format(
    getpass.getuser(), platform.node())

ROOT_DEVICE_MANUFACTURER = 'Matt Joiner'
ROOT_DEVICE_MODEL_NAME = 'pydlnadms 0.1'
DEVICE_DESC_SERVICE_FIELDS = 'serviceType', 'serviceId', 'SCPDURL', 'controlURL', 'eventSubURL'
Service = collections.namedtuple(
    'Service',
    DEVICE_DESC_SERVICE_FIELDS + ('xmlDescription',))
RESOURCE_PATH = '/res'
ICON_PATH = '/icon'
# flags are in hex. trailing 24 zeroes, 26 are after the space
# "DLNA.ORG_OP=" time-seek-range-supp bytes-range-header-supp
#CONTENT_FEATURES = 'DLNA.ORG_OP=10;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=017000 00000000000000000000000000000000'
SSDP_PORT = 1900
SSDP_MCAST_ADDR = '239.255.255.250'
TIMESEEKRANGE_DLNA_ORG = 'TimeSeekRange.dlna.org'
CONTENTFEATURES_DLNA_ORG = 'contentFeatures.dlna.org'


class DLNAContentFeatures:

    def __init__(self):
        self.support_time_seek = False
        self.support_range = False
        self.transcoded = False

    def __str__(self):
        return 'DLNA.ORG_OP={}{};DLNA.ORG_CI={};DLNA.ORG_FLAGS=017000 00000000000000000000000000000000'.format(
            ('1' if self.support_time_seek else '0'),
            ('1' if self.support_range else '0'),
            ('1' if self.transcoded else '0'),)


def make_xml_service_description(actions, statevars):
    from xml.etree.ElementTree import Element, tostring, SubElement
    scpd = Element('scpd', xmlns='urn:schemas-upnp-org:service-1-0')
    specVersion = SubElement(scpd, 'specVersion')
    SubElement(specVersion, 'major').text = '1'
    SubElement(specVersion, 'minor').text = '0'
    actionList = SubElement(scpd, 'actionList')
    for action in actions:
        action_elt = SubElement(actionList, 'action')
        SubElement(action_elt, 'name').text = action[0]
        argumentList = SubElement(action_elt, 'argumentList')
        for name, dir, var in action[1]:
            argument = SubElement(argumentList, 'argument')
            SubElement(argument, 'name').text = name
            SubElement(argument, 'direction').text = dir
            SubElement(argument, 'relatedStateVariable').text = var
    serviceStateTable = SubElement(scpd, 'serviceStateTable')
    for name, datatype, *rest in statevars:
        stateVariable = SubElement(serviceStateTable, 'stateVariable', sendEvents='no')
        SubElement(stateVariable, 'name').text = name
        SubElement(stateVariable, 'dataType').text = datatype
        if rest:
            assert len(rest) == 1
            allowedValueList = SubElement(stateVariable, 'allowedValueList')
            for av in rest[0]:
                SubElement(allowedValueList, 'allowedValue').text = av
    return tostring(scpd)#.encode('utf-8')

SERVICE_LIST = []
for service, domain, version, actions, statevars in [
            ('ContentDirectory', None, 1, [
                ('Browse', [
                    ('ObjectID', 'in', 'A_ARG_TYPE_ObjectID'),
                    ('BrowseFlag', 'in', 'A_ARG_TYPE_BrowseFlag'),
                    ('StartingIndex', 'in', 'A_ARG_TYPE_Index'),
                    ('RequestedCount', 'in', 'A_ARG_TYPE_Count'),
                    ('Result', 'out', 'A_ARG_TYPE_Result'),
                    ('NumberReturned', 'out', 'A_ARG_TYPE_Count'),
                    ('TotalMatches', 'out', 'A_ARG_TYPE_Count')])], [
                ('A_ARG_TYPE_ObjectID', 'string'),
                ('A_ARG_TYPE_Result', 'string'),
                ('A_ARG_TYPE_BrowseFlag', 'string', [
                    'BrowseMetadata', 'BrowseDirectChildren']),
                ('A_ARG_TYPE_Index', 'ui4'),
                ('A_ARG_TYPE_Count', 'ui4')]),
            ('ConnectionManager', None, 1, (), ()),
            #('X_MS_MediaReceiverRegistrar', 'microsoft.com', 1, (), ()),
        ]:
    SERVICE_LIST.append(Service(
        serviceType='urn:{}:service:{}:{}'.format(
            'schemas-upnp-org' if domain is None else domain,
            service, version),
        serviceId='urn:{}:serviceId:{}'.format(
            'upnp-org' if domain is None else domain, service),
        SCPDURL='/'+service+'.xml',
        controlURL='/ctl/'+service,
        eventSubURL='/evt/'+service,
        xmlDescription=make_xml_service_description(actions, statevars)))

HTTP_BODY_SEPARATOR = b'\r\n' * 2

def http_message(first_line, headers, body):
    return (first_line + '\r\n' + httpify_headers(headers) + '\r\n').encode('utf-8') + body


class HTTPMessage:

    def __init__(self, first_line, headers, body):
        self.first_line = first_line
        self.headers = headers
        self.body = body

    def to_bytes(self):
        return (
            self.first_line + '\r\n' +
            httpify_headers(self.headers) + '\r\n'
        ).encode('utf-8') + self.body


class HTTPRequest:

    __slots__ = 'method', 'path', 'protocol', 'headers', 'body', 'query'

    def __init__(self, method, resource, headers=None, body=b''):
        self.method = method
        self.headers = headers or {}
        split_result = urllib.parse.urlsplit(resource)
        self.query = urllib.parse.parse_qs(split_result.query)
        self.path = urllib.parse.unquote(split_result.path)
        if split_result.fragment:
            logger.warning(
                'Unused fragment in HTTP request resource: %r',
                split_result.fragment)
        self.body = body

    def __setitem__(self, key, value):
        self.headers[key.upper()] = value.strip()

    def __getitem__(self, key):
        return self.headers[key.upper()]

    def __contains__(self, key):
        return key.upper() in self.headers

    def to_bytes(self):
        return HTTPMessage(
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


class HTTPResponse:

    from http.client import responses

    def __init__(self, headers=None, body=b'', code=None, reason=None):
        self.headers = dict(headers) or {}
        self.body = body
        self.code = code
        self.reason = reason

    def to_bytes(self):
        return HTTPMessage(
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
            value = str(value)
            yield ':'.join([str(key), ' '+value if value else value])
    return '\r\n'.join(chain(lines(), ['']))

def rfc1123_date():
    import time
    return time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())


class RequestHandlerContext:
    __slots__ = 'socket', 'on_done', 'request', 'dms'


class HTTPConnection:

    logger = logging.getLogger('http.conn')
    HTTPException = http.client.HTTPException

    def __init__(self, socket, dms):
        self.dms = dms
        self.socket = socket

    def read_request(self):
        buffer = b''
        while True:
            # determine bufsize so that body is left in the socket
            #
            peek_data = self.socket.recv(0x1000, socket.MSG_PEEK)
            index = (buffer + peek_data).find(HTTP_BODY_SEPARATOR)
            assert index >= -1, index
            if index == -1:
                bufsize = len(peek_data)
            else:
                bufsize = index - len(buffer) + len(HTTP_BODY_SEPARATOR)
            assert bufsize <= len(peek_data), (bufsize, len(peek_data))

            data = self.socket.recv(bufsize)
            assert data == peek_data[:bufsize], (data, peek_data)
            if not data:
                if buffer:
                    self.logger.error('Received incompleted HTTP request')
                else:
                    self.logger.info(
                        'Peer closed connection from %s',
                        pretty_sockaddr(self.socket.peername))
                return None
            buffer += data
            del data, bufsize, peek_data

            if index == -1:
                # complete header hasn't arrived yet
                continue
            del index

            try:
                request = HTTPRequest.from_bytes(buffer)
            except ValueError:
                self.logger.exception('Failed to parse HTTP request')
                raise HTTPException(http.client.BAD_REQUEST)
            self.logger.debug('Received HTTP request:\n%s', buffer.decode('utf-8'))
            del buffer
            return request
        assert False

    def run(self):
        try:
            while True:
                context = RequestHandlerContext()
                context.socket = self.socket
                context.dms = self.dms
                try:
                    context.request = self.read_request()
                    if context.request is None:
                        return
                    handler = self.create_handler(context.request.method, context.request.path)
                except self.HTTPException as exc:
                    buffer = HTTPResponse([
                            ('Content-Length', 0),
                            ('Date', rfc1123_date()),
                            ('SERVER', SERVER_FIELD),
                        ], code=exc.args[0]).to_bytes()
                    self.logger.debug(
                        'Response to %s:\n%s',
                        pretty_sockaddr(context.socket.peername),
                        buffer.decode())
                    handler = BufferRequestHandler(buffer)
                # return true if another request can now be handled
                if not handler(context):
                    break
        finally:
            self.socket.close()

    def create_handler(self, method, path):
        def send_description(desc):
            return BufferRequestHandler(HTTPResponse([
                    ('CONTENT-LENGTH', str(len(desc))),
                    ('CONTENT-TYPE', 'text/xml'),
                    ('DATE', rfc1123_date()),
                    ('SERVER', SERVER_FIELD),
                ], desc, code=200).to_bytes())
        if method in ['GET']:
            if path == ROOT_DESC_PATH:
                return send_description(self.dms.device_desc)
            for service in SERVICE_LIST:
                if path == service.SCPDURL:
                    return send_description(service.xmlDescription)
            if path in [RESOURCE_PATH, ICON_PATH]:
                return ResourceRequestHandler()
            else:
                raise self.HTTPException(http.client.NOT_FOUND)
        elif method in ['POST']:
            if path in (service.controlURL for service in SERVICE_LIST):
                return SOAPRequestHandler()
            raise self.HTTPException(http.client.NOT_FOUND)
        elif method in ['SUBSCRIBE']:
            for service in SERVICE_LIST:
                if path == service.eventSubURL:
                    raise self.HTTPException(http.client.NOT_IMPLEMENTED)
            else:
                raise self.HTTPException(http.client.NOT_FOUND)
        else:
            raise self.HTTPException(http.client.NOT_IMPLEMENTED)
        assert False


class HTTPServer:

    logger = logger

    def __init__(self, port, on_accept):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        # TODO allow binding to specific interfaces
        while True:
            try:
                self.socket.bind(('', port))
            except socket.error as exc:
                if exc.errno != errno.EADDRINUSE:
                    raise
            else:
                self.logger.info('HTTP server listening on %s', pretty_sockaddr(self.socket.getsockname()))
                break
            port += 1
        # TODO use the socket backlog default
        self.socket.listen(5)
        self.on_accept = on_accept

    def run(self):
        while True:
            sock, addr = self.socket.accept()
            self.logger.info('Accepted connection from %s', pretty_sockaddr(addr))
            self.on_accept(sock)

    def __repr__(self):
        return '<{}.{} socket={}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.socket)


def guess_mimetype(path):
    from mimetypes import guess_type
    type = guess_type(path)[0]
    if type is None:
        type = 'application/octet-stream'
    #if type == 'video/MP2T':
    #    type = 'video/mpeg'
    return type
    #return 'video/x-msvideo'
    #return 'video/MP2T'


class FileResource:

    def __init__(self, path, start, end):
        self.file = open(path, 'rb')
        self.start = start
        self.end = end
        self.file.seek(start)

    def read(self, count):
        if self.end is not None:
            count = min(self.end - self.file.tell(), count)
        return self.file.read(count)

    @property
    def size(self):
        return os.fstat(self.file.fileno()).st_size

    @property
    def length(self):
        if self.end is None:
            return None
        else:
            return self.end - self.start

    def __repr__(self):
        return '<FileResource path=%r, start=%r, end=%r>' % (self.file.name, self.start, self.end)

    def close(self):
        logging.debug('Closing %r', self)
        self.file.close()

    def fileno(self):
        return self.file.fileno()


def dlna_npt_sec(npt_time):
    if ':' in npt_time:
        hours, mins, secs = map(float, npt_time.split(':'))
        return datetime.timedelta(hours=hours, minutes=mins, seconds=secs).total_seconds()
    else:
        return float(npt_time)


        #elif False: pass
            #args = ['mencoder']
            # -ss and -endpos (not relative)
            #~ '-oac', 'lavc', '-ovc', 'lavc', '-of', 'mpegts', '-mpegopts',
            #~ 'format=dvd:tsaf', '-vf', 'scale=720:576,harddup', '-srate', '48000',
            #~ '-af', 'lavcresample=48000', '-lavcopts',
            #~ 'vcodec=mpeg2video:vrc_buf_size=1835:vrc_maxrate=9800:vbitrate=5000:keyint=15:vstrict=0:acodec=ac3:abitrate=192:aspect=16/9', '-ofps', '25',
            #~ '-o', '/dev/stdout', path
        #elif False: pass
            #~ args = ['vlc', '-I', 'dummy']
            #~ args += [
                #~ '--sout', '#transcode{vcodec=mp2v,fps=24,vb=6000}:std{mux=ts,access=file,dst=/dev/stdout}',
            # --start-time and --end-time (relative)
                #~ path,


class TranscodeResource:

    logger = logging

    def __repr__(self):
        return '<{} cmdline={!r} pid={} exitcode={}>'.format(
            self.__class__.__name__,
            subprocess.list2cmdline(self.args),
            self._child.pid,
            self._child.returncode)

    def __init__(self, path, start, end):
        args = [
            'ffmpeg',
            '-threads', '2',
            '-async', '1',
            # video and audio are usually put here, sometimes commentary is picked instead by ffmpeg if these streams aren't explicitly set
            '-map', '0.0',
            '-map', '0.1',
        ]
        if start:
            args += ['-ss', start]
        if end:
            if start:
                args += ['-t', str(dlna_npt_sec(end) - dlna_npt_sec(start))]
            else:
                args += ['-t', end]
        args += [
            '-i', path,
            '-vcodec', 'mpeg2video',
            '-sameq',
            '-acodec', 'ac3', '-ab', '192k',
            '-f', 'mpegts',
            '-y', '/dev/stdout'
        ]
        logging.debug('Starting transcoder with arguments: %r', args)
        self._child = subprocess.Popen(
            args,
            stdin=open(os.devnull, 'rb'),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        self.args = args
        self._stderr_thread = threading.Thread(target=self._log_stderr)
        self._stderr_thread.start()

    def fileno(self):
        return self._child.stdout.fileno()

    def __del__(self):
        self.close()

    def close(self):
        if self._child.returncode is None:
            self._child.kill()
            logging.debug('Terminating transcoder: %s', self)
        self._stderr_thread.join()

    def _log_stderr(self):
        output = self._child.stderr.read()
        assert self._child.returncode is None, self._child.returncode
        if self._child.wait():
            level = logging.ERROR
        else:
            level = logging.DEBUG
        self.logger.log(level, '%s: Transcoder stderr:\n%s', self, output.decode('cp1252'))

    def read(self, count):
        output = self._child.stdout.read(count)
        logger.debug('Got %r bytes from transcoder stdout: %s', (len(output) if output else output), self)
        return output

    @property
    def length(self):
        return None


class HTTPRange:

    def __init__(self):
        self.start = '0'
        self.end = ''
        self.size = ''

    @classmethod
    def from_string(class_, str_):
        instance = class_()
        if '/' in str_:
            range_, instance.size = str_.split('/')
        else:
            range_ = str_
        instance.start, instance.end = range_.split('-')
        return instance

    def __str__(self):
        s = self.start + '-' + self.end
        if self.size:
            s += '/' + str(self.size)
        return s


class HTTPRangeField(dict):

    @classmethod
    def from_string(class_, str_):
        instance = class_()
        for forms_ in str_.split():
            units, range_ = forms_.split('=')
            instance[units] = HTTPRange.from_string(range_)
        return instance

    def __str__(self):
        return ' '.join('{}={}'.format(units, range) for units, range in self.items())


class DiscontiguousBuffer:

    def __init__(self):
        self._deque = collections.deque()
        self._size = 0

    def append(self, item):
        size = len(item)
        self._size += size
        return self._deque.append((item, size))

    def appendleft(self, item):
        size = len(item)
        self._size += size
        return self._deque.appendleft((item, size))

    def pop(self):
        item, size = self._deque.pop()
        self._size -= size
        return item

    def popleft(self):
        item, size = self._deque.popleft()
        self._size -= size
        return item

    def size(self):
        assert self._size >= 0, self._size
        return self._size

    def __getitem__(self, key):
        return self._deque[key][0]

    def __len__(self):
        return len(self._deque)

    def __repr__(self):
        return '<%s size=%d, len=%d>' % (self.__class__.__name__, self.size(), len(self._deque))


class QueueBuffer:
    '''A thread-safe FIFO that caps the total length of all items held.'''

    def __init__(self, maxbytes):
        self._deque = collections.deque()
        self._curbytes = 0
        self._maxbytes = maxbytes
        self._cond = threading.Condition()
        self._closed = False

    def put(self, item, always=False):
        '''
        Put an item into the queue.
        If always, the buffer size limit is ignored.
        Blocks until the buffer usage drops below the maximum.
        Returns True if the queue is still open, and False if it's closed.
        '''
        nbytes = len(item)
        with self._cond:
            while True:
                if self.closed:
                    return False
                elif self._curbytes >= self._maxbytes and not always:
                    self._cond.wait()
                else:
                    self._curbytes += nbytes
                    self._deque.append((item, nbytes))
                    self._cond.notify_all()
                    return True

    def get(self):
        '''
        Returns an item from the queue.
        Blocks until an item is available.
        Returns None if no item is available and the queue is closed.
        '''
        with self._cond:
            while True:
                if self._deque:
                    item, nbytes = self._deque.popleft()
                    self._curbytes -= nbytes
                    assert self._curbytes >= 0
                    self._cond.notify_all()
                    return item
                elif self.closed:
                    return None
                else:
                    self._cond.wait()

    @property
    def closed(self):
        return self._closed

    @property
    def empty(self):
        return self._curbytes == 0

    def close(self):
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def __str__(self):
        return '<{} curbytes={} maxbytes={} nchunks={}>'.format(
            self.__class__.__name__,
            self._curbytes,
            self._maxbytes,
            len(self._deque))


class ResourceRequestHandler:

    def __init__(self):
        self.buffer = QueueBuffer(0x2000000) # 32MiB
        self.resource = None

    def __repr__(self):
        return '<{} buffer={} resource={}>'.format(
            self.__class__.__name__,
            self.buffer,
            self.resource)

    def _start_response(self, request):
        path = request.query['path'][-1]
        response_headers = [
            ('Server', SERVER_FIELD),
            ('Date', rfc1123_date()),
            ('Ext', None),
            ('transferMode.dlna.org', 'Streaming'),
            # TODO: wtf does this mean?
            #('realTimeInfo.dlna.org', 'DLNA.ORG_TLAG=*')
        ]
        content_features = DLNAContentFeatures()
        if 'transcode' in request.query:
            content_features.support_time_seek = True
            content_features.transcoded = True
            if TIMESEEKRANGE_DLNA_ORG in request:
                ranges_field = HTTPRangeField.from_string(request[TIMESEEKRANGE_DLNA_ORG])
            else:
                ranges_field = HTTPRangeField({'npt': HTTPRange()})
            npt_range = ranges_field['npt']
            self.resource = TranscodeResource(path, npt_range.start, npt_range.end)
            npt_range.size = '*'
            response_headers += [
                (TIMESEEKRANGE_DLNA_ORG, HTTPRangeField({'npt': npt_range})),
                ('Content-type', 'video/mpeg'),]
        elif 'thumbnail' in request.query:
            assert False, 'Yay!!'
        else:
            content_features.support_range = True
            if 'Range' in request:
                ranges_field = HTTPRangeField.from_string(request['Range'])
            else:
                ranges_field = HTTPRangeField({'bytes': HTTPRange()})
            bytes_range = ranges_field['bytes']
            self.resource = FileResource(
                path,
                int(bytes_range.start) if bytes_range.start else 0,
                int(bytes_range.end) + 1 if bytes_range.end else None)
            bytes_range.size = self.resource.size
            response_headers += [
                ('Content-Range', HTTPRangeField({'bytes': bytes_range})),
                ('Accept-Ranges', 'bytes'),
                ('Content-Type', guess_mimetype(path))]
        if self.resource.length:
            response_headers += [('Content-Length', self.resource.length)]
        else:
            response_headers += [('Connection', 'close')]

        # put the resource in non-blocking mode to maximize responsiveness
        #
        #~ flags = fcntl.fcntl(self.resource, fcntl.F_GETFL)
        #~ fcntl.fcntl(self.resource, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        # put the response header as the first chunk in the buffer
        #
        response_headers += [(CONTENTFEATURES_DLNA_ORG, content_features)]
        buf = HTTPResponse(response_headers, code=206).to_bytes()
        # TODO it's silly converting to bytes and then back again to print it
        # TODO decode using the HTTP standard encoding if one exists
        logging.debug('Response header:\n%s', buf.decode())
        self.buffer.put(buf, always=True)

    def _feed_buffer(self):
        try:
            while True:
                #~ readset, writeset, excptset = select.select([self.resource], [], [])
                #~ assert not writeset and not excptset
                #~ if self.resource in readset:
                chunk = self.resource.read(0x20000) # 128KiB
                if not chunk:
                    break
                logging.debug('Got %d bytes from resource: %r', len(chunk), self)
                if not self.buffer.put(chunk):
                    break
                #~ else:
                    #~ assert not readset
        finally:
            self.buffer.close()
            logging.debug('Buffer feeder terminated: %s', self)

    def __del__(self):
        self.destroy()

    def destroy(self):
        self.buffer.close()
        if self.resource is not None:
            self.resource.close()

    def __call__(self, context):
        try:
            self._start_response(context.request)
            thread = threading.Thread(target=self._feed_buffer)
            thread.start()
            self.socket = context.socket
            while not (self.buffer.closed and self.buffer.empty):
                if self.buffer.empty:
                    logging.warning('Buffer underflow: %s', self)
                chunk = self.buffer.get()
                while chunk:
                    try:
                        chunk = chunk[self.socket.send(chunk):]
                    except socket.error as exc:
                        if exc.errno in [errno.EPIPE, errno.ECONNRESET]:
                            logging.info('Peer closed connection: %s', self)
                            return False
            return self.resource.length is not None
        finally:
            self.destroy()
            thread.join()


class BufferRequestHandler:

    def __init__(self, buffer):
        self.buffer = buffer

    def __call__(self, context):
        self.socket = context.socket
        while self.buffer:
            self.buffer = self.buffer[self.socket.send(self.buffer):]
        return True


def soap_action_response(service_type, action_name, arguments):
    return '''<?xml version="1.0"?>
<s:Envelope
        xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
        s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:{actionName}Response xmlns:u="{serviceType}">
            {argumentXML}
        </u:{actionName}Response>
    </s:Body>
</s:Envelope>'''.format(
        actionName=action_name,
        argumentXML='\n'.join([
            '<{argumentName}>{value}</{argumentName}>'.format(
                argumentName=name, value=value) for name, value in arguments]),
        serviceType=service_type)

def didl_lite(content):
    return ('''<DIDL-Lite
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/"
    xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/"
    xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/">
        ''' + content + r'</DIDL-Lite>')

#objects = Objects()
#objects.add_path('/media/data/towatch')
#<res size="1468606464" duration="1:57:48.400" bitrate="207770" sampleFrequency="48000" nrAudioChannels="6" resolution="656x352" protocolInfo="http-get:*:video/avi:DLNA.ORG_OP=01;DLNA.ORG_CI=0">http://192.168.24.8:8200/MediaItems/316.avi</res>


class ContentDirectoryService:

    def __init__(self, root_id_path, res_scheme, res_netloc):
        self.root_id_path = root_id_path
        self.res_scheme = res_scheme
        self.res_netloc = res_netloc

    def list_dlna_dir(self, path):
        '''Yields a sequence of Entry's'''
        Entry = collections.namedtuple('Entry', ['path', 'transcode', 'title', 'mimetype'])
        try:
            names = os.listdir(path)
        except:
            logger.warning('Error listing directory: %s', sys.exc_info()[1])
            names = []
        for name in sorted(names, key=str.lower):
            entry_path = os.path.join(path, name)
            mimetype = guess_mimetype(entry_path)
            entry = Entry(path=entry_path, transcode=False, title=name, mimetype=mimetype)
            yield entry
            if mimetype and mimetype.split('/')[0] == 'video':
                # forward slashes cannot be used in normal file names >:D
                yield entry._replace(transcode=True, title=name+'/transcode')

    def object_xml(self, parent_id, cdentry):
        '''Returns XML describing a UPNP object'''
        path = cdentry.path
        transcode = cdentry.transcode
        title = cdentry.title
        isdir = os.path.isdir(path)
        element = etree.Element(
            'container' if isdir else 'item',
            id=path, parentID=parent_id, restricted='1')
        # despite being optional, VLC requires childCount to browse subdirectories
        if isdir:
            element.set('childCount', str(sum(1 for e in self.list_dlna_dir(path))))
        etree.SubElement(element, 'dc:title').text = title
        class_elt = etree.SubElement(element, 'upnp:class')
        if isdir:
            class_elt.text = 'object.container.storageFolder'
        else:
            class_elt.text = 'object.item.videoItem'
            etree.SubElement(element, 'upnp:icon').text = urllib.parse.urlunsplit((
                self.res_scheme,
                self.res_netloc,
                ICON_PATH,
                urllib.parse.urlencode({'path': path, 'thumbnail': 1}),
                None))
        content_features = DLNAContentFeatures()
        if transcode:
            content_features.support_time_seek = True
            content_features.transcoded = True
        else:
            content_features.support_range = True
        res_elt = etree.SubElement(element, 'res',
            protocolInfo='http-get:*:{}:{}'.format(
                '*' if isdir else 'video/mpeg' if transcode else cdentry.mimetype,
                content_features))
        res_elt.text = urllib.parse.urlunsplit((
            self.res_scheme,
            self.res_netloc,
            RESOURCE_PATH,
            urllib.parse.urlencode([('path', path)] + ([('transcode', '1')] if transcode else [])),
            None))
        if not isdir:
            try:
                res_elt.set('size', str(os.path.getsize(path)))
            except OSError as exc:
                logging.warning('%s', exc)
        if not transcode:
            from metadata_ff import res_data
            for attr, value in res_data(path).items():
                res_elt.set(attr, str(value))
        return etree.tostring(element, encoding='unicode')

    def path_to_object_id(root_path, path):
        # TODO prevent escaping root directory
        path = os.path.normpath(path)
        if path == root_path:
            return '0'
        else:
            return path

    def object_id_to_path(self, object_id):
        if object_id == '0':
            return self.root_id_path
        else:
            return object_id

    def Browse(self, BrowseFlag, StartingIndex, RequestedCount, ObjectID, Filter, SortCriteria):
        '''(list of CD objects in XML, total possible elements)'''
        path = self.object_id_to_path(ObjectID)
        if BrowseFlag == 'BrowseDirectChildren':
            children = list(self.list_dlna_dir(path))
            start = int(StartingIndex)
            count = int(RequestedCount)
            end = len(children)
            if count:
                end = min(start + count, end)
            result_elements = []
            for index in range(start, end):
                result_elements.append(self.object_xml(ObjectID, children[index]))
            total_matches = len(children)
        else: # TODO check other flags
            parent_id = path_to_object_id(os.path.normpath(os.path.split(path)[0]))
            result_elements = [
                self.object_xml(parent_id, path, '??ROOT??', None)
            ]
            total_matches = 1
        logging.debug('ContentDirectory::Browse result:\n%s', pprint.pformat(result_elements))
        return dict(
            Result=xml_escape(didl_lite(''.join(result_elements))),
            NumberReturned=len(result_elements),
            TotalMatches=total_matches)


class SOAPRequestHandler:

    def read_soap_request(self):
        buffer = b''
        while len(buffer) != self.content_length:
            incoming = self.socket.recv(self.content_length - len(buffer))
            if not incoming:
                # TODO send SOAP error response?
                logging.error('SOAP request body was not completed: %r', buffer)
                return
            buffer += incoming
        return buffer

    def __call__(self, context):
        request = context.request
        soapact = request['soapaction']
        assert soapact[0] == '"' and soapact[-1] == '"', soapact
        self.service_type, self.action = soapact[1:-1].rsplit('#', 1)
        self.content_length = int(request['content-length'])
        self.dms = context.dms
        self.request = request
        self.socket = context.socket

        # we're already looking at the envelope, perhaps I should wrap this
        # with a Document so that absolute lookup is done instead? TODO
        soap_request = etree.fromstring(self.read_soap_request())
        action_elt = soap_request.find(
            '{{{s}}}Body/{{{u}}}{action}'.format(
                s='http://schemas.xmlsoap.org/soap/envelope/',
                u=self.service_type,
                action=self.action))
        in_args = {}
        for child_elt in action_elt.getchildren():
            assert not child_elt.getchildren()
            key = child_elt.tag
            value = child_elt.text
            assert key not in in_args, key
            in_args[key] = value
        out_args = getattr(self, 'soap_' + self.action)(**in_args)
        response_body = soap_action_response(
            self.service_type,
            self.action, out_args.items()).encode('utf-8')
        buffer = HTTPResponse([
            ('CONTENT-LENGTH', str(len(response_body))),
            ('CONTENT-TYPE', 'text/xml; charset="utf-8"'),
            ('DATE', rfc1123_date()),
            ('EXT', ''),
            ('SERVER', SERVER_FIELD)
        ], response_body, code=200).to_bytes()
        while buffer:
            buffer = buffer[self.socket.send(buffer):]

    def soap_Browse(self, **soap_args):
        cds = ContentDirectoryService(self.dms.path, 'http', self.request['host'])
        return cds.Browse(**soap_args)

    def soap_GetSortCapabilities(self, **soap_args):
        return {'SortCaps': 'dc:title'}


class SocketWrapper(socket.socket):

    logger = logging.getLogger('socket')

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
        sent = self.__socket.send(data)
        self.logger.debug('%s sent %d bytes', self, sent)
        return sent

    def sendto(self, buf, addr):
        sent = self.__socket.sendto(buf, addr)
        self.logger.debug('Sent %s bytes from %s to %s: %r', sent,
            self.__socket.getsockname(), addr, buf[:sent])
        return sent

    def recv(self, bufsize, flags=0):
        data = self.__socket.recv(bufsize, flags)
        from socket import MSG_PEEK
        if flags & MSG_PEEK:
            self.logger.debug('Peeked at %s bytes', len(data))
        else:
            self.logger.debug('Received %s bytes on %s%s: %r',
                len(data),
                self.__socket.getsockname(),
                self.peername,
                data)
        return data

    def recvfrom(self, *args, **kwds):
        buf, addr = self.__socket.recvfrom(*args, **kwds)
        self.logger.debug('Received %s bytes on %s%s: %r',
            len(buf), self.sockname, addr, buf)
        return buf, addr

    def fileno(self):
        return self.__socket.fileno()

    def close(self):
        assert not self.__closed
        self.__socket.close()
        self.logger.debug('Closed socket: %s', self)
        self.__closed = True

    def __repr__(self):
        return '<SocketWrapper sock={} peer={}>'.format(
            self.sockname,
            self.peername,)

    def __getattr__(self, attr):
        return getattr(self.__socket, attr)


class SSDPAdvertiser:

    logger = logger

    def __init__(self, dms):
        self.dms = dms
        self.events = Events()

    @property
    def http_address(self):
        return self.dms.http_server.socket.getsockname()

    @property
    def usn_from_target(self):
        return self.dms.usn_from_target

    @property
    def notify_interval(self):
        return self.dms.notify_interval

    @property
    def notify_interfaces(self):
        from getifaddrs import getifaddrs, IFF_LOOPBACK
        from socket import AF_INET
        for ifaddr in getifaddrs():
            if ifaddr.family == AF_INET: #and not ifaddr.flags & IFF_LOOPBACK:
                yield ifaddr.family, ifaddr.addr

    def ssdp_multicast(self, family, addr, buf):
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, False)
        s.bind((addr[0], 0)) # to the interface on any port
        s = SocketWrapper(s)
        s.sendto(buf, (SSDP_MCAST_ADDR, SSDP_PORT))
        s.close()

    def notify_byebye(self):
        for nt in self.dms.all_targets:
            for family, addr in self.notify_interfaces:
                buf = HTTPRequest('NOTIFY', '*', (
                    ('HOST', '{}:{:d}'.format(SSDP_MCAST_ADDR, SSDP_PORT)),
                    ('NT', nt),
                    ('USN', self.dms.usn_from_target(nt)),
                    ('NTS', 'ssdp:byebye'),)).to_bytes()
                self.ssdp_multicast(family, addr, buf)
        self.logger.debug('Sent SSDP byebye notifications')

    def notify_alive(self):
        # TODO for each interface
        # sends should also be delayed 100ms by eventing
        for family, addr in self.notify_interfaces:
            for nt in self.dms.all_targets:
                buf = HTTPRequest('NOTIFY', '*', [
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
                self.events.add(
                    self.ssdp_multicast,
                    args=[family, addr, buf],
                    delay=random.uniform(0, 0.1))
            self.logger.info('Sending SSDP alive notifications from %s', addr[0])
        self.events.add(self.notify_alive, delay=self.notify_interval)

    def run(self):
        self.events.add(self.notify_alive, delay=0.1)
        while True:
            timeout = self.events.poll()
            logger.debug('Waiting for next advertisement event: %r', timeout)
            time.sleep(timeout)

class SSDPResponder:

    logger = logger

    def process_message(self, data, peeraddr):
        request = HTTPRequest.from_bytes(data)
        if request.method != 'M-SEARCH':
            logging.info('Ignoring %r request from %s', request.method, peeraddr)
            return
        st = request['st']
        if st in self.dms.all_targets:
            sts = [st]
        elif st == 'ssdp:all':
            sts = self.dms.all_targets
        else:
            self.logger.debug('Ignoring M-SEARCH for %r from %s', st, peeraddr[0])
            return
        for st in sts:
            self.send_msearch_reply(peeraddr, st)
            self.events.add(
                self.send_msearch_reply,
                args=[peeraddr, st],
                delay=random.uniform(1, float(request['MX'])))

    @property
    def usn_from_target(self):
        return self.dms.usn_from_target

    @property
    def http_address(self):
        return self.dms.http_server.socket.getsockname()

    @property
    def max_age(self):
        return self.dms.notify_interval * 2 + EXPIRY_FUDGE

    def send_msearch_reply(self, peeraddr, st):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(peeraddr)
        sock = SocketWrapper(sock)
        buf = HTTPResponse([
                ('CACHE-CONTROL', 'max-age={:d}'.format(self.max_age)),
                ('DATE', rfc1123_date()),
                ('EXT', ''),
                ('LOCATION', 'http://{}:{:d}{}'.format(
                    sock.getsockname()[0],
                    self.http_address[1],
                    ROOT_DESC_PATH)),
                ('SERVER', SERVER_FIELD),
                ('ST', st),
                ('USN', self.usn_from_target(st))
            ], code=200
        ).to_bytes()
        sock.send(buf)
        sock.close()
        self.logger.debug('Responded to M-SEARCH from %s', pretty_sockaddr(peeraddr))

    def __init__(self, dms):
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
        self.socket = SocketWrapper(s)
        self.events = Events()
        self.dms = dms

    def run(self):
        while True:
            # MTU should limit UDP packet sizes to well below this
            data, addr = self.socket.recvfrom(0x1000)
            assert len(data) < 0x1000, len(addr)
            self.process_message(data, addr)


def make_device_desc(udn):
    from xml.etree.ElementTree import Element, tostring, SubElement
    root = Element('root', xmlns='urn:schemas-upnp-org:device-1-0')
    specVersion = SubElement(root, 'specVersion')
    SubElement(specVersion, 'major').text = '1'
    SubElement(specVersion, 'minor').text = '0'
    #SubElement(root, 'URLBase').text =
    device = SubElement(root, 'device')
    SubElement(device, 'deviceType').text = ROOT_DEVICE_DEVICE_TYPE
    SubElement(device, 'friendlyName').text = ROOT_DEVICE_FRIENDLY_NAME
    SubElement(device, 'manufacturer').text = ROOT_DEVICE_MANUFACTURER
    SubElement(device, 'modelName').text = ROOT_DEVICE_MODEL_NAME
    SubElement(device, 'UDN').text = udn
    iconList = SubElement(device, 'iconList')
    for icon_attrs in [
            ('image/png', 48, 48, 8, '/icon?path=VGC+Sonic.png'),
            ('image/png', 128, 128, 8, '/icon?path=VGC+Sonic+128.png'),]:
        icon = SubElement(iconList, 'icon')
        for name, text in zip(('mimetype', 'width', 'height', 'depth', 'url'), icon_attrs):
            SubElement(icon, name).text = str(text)
    serviceList = SubElement(device, 'serviceList')
    for service in SERVICE_LIST:
        service_elt = SubElement(serviceList, 'service')
        for tag in DEVICE_DESC_SERVICE_FIELDS:
            SubElement(service_elt, tag).text = getattr(service, tag)
    return tostring(root, encoding='utf-8')#.encode('utf-8')


class Events:

    def __init__(self):
        self.events = []

    def add(self, callback, args=None, delay=None):
        heapq.heappush(self.events, (time.time() + delay, callback, args))

    def poll(self):
        # execute any events that've passed their due times
        while True:
            if self.events:
                timeout = self.events[0][0] - time.time()
                if timeout >= 0:
                    # event not ready, so return the timeout
                    return timeout
                # event ready, execute it
                callback, args = heapq.heappop(self.events)[1:]
                callback(*([] if args is None else args))
            else:
                # no events pending, so there is no timeout
                return None


def exception_logging_decorator(func):
    def callable():
        try:
            return func()
        except:
            logger.exception('Exception in thread %r:', threading.current_thread())
            raise
    return callable


class DigitalMediaServer:

    def __init__(self, port, path):
        # use a hash of the friendly name (should be unique enough)
        self.device_uuid = 'uuid:deadbeef-0000-0000-0000-{}'.format(
            '{:012x}'.format(abs(hash(ROOT_DEVICE_FRIENDLY_NAME)))[-12:])
        logger.info('DMS UUID is %r', self.device_uuid)
        self.notify_interval = 895
        self.device_desc = make_device_desc(self.device_uuid)
        self.http_server = HTTPServer(port, self.on_server_accept)
        self.ssdp_advertiser = SSDPAdvertiser(self)
        self.ssdp_responder = SSDPResponder(self)
        self.path = path
        self.run()

    def run(self):
        threads = []
        for runnable in [self.http_server, self.ssdp_advertiser, self.ssdp_responder]:
            thread = threading.Thread(target=exception_logging_decorator(runnable.run), name=runnable.__class__.__name__)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        while True:
            for thread in threads:
                thread.join(0.33)
                if not thread.is_alive():
                    logger.warning('A required thread has terminated: %r', thread)
                    return

    def on_server_accept(self, sock):
        blah = HTTPConnection(SocketWrapper(sock), self)
        thread = threading.Thread(target=exception_logging_decorator(blah.run), name=blah)
        thread.daemon = True
        thread.start()

    @property
    def all_targets(self):
        yield UPNP_ROOT_DEVICE
        yield self.device_uuid
        yield ROOT_DEVICE_DEVICE_TYPE
        for service in SERVICE_LIST:
            yield service.serviceType

    def usn_from_target(self, target):
        if target == self.device_uuid:
            return target
        else:
            return self.device_uuid + '::' + target


def main():
    from optparse import OptionParser
    parser = OptionParser(
        usage='%prog [options] [PATH]',
        description='Serves media from the given PATH over UPnP AV and DLNA.')
    parser.add_option(
        '-p', '--port', type='int', default=1337,
        help='media server listen PORT')
    parser.add_option(
        '--logging_conf',
        help='Path of Python logging configuration file')
    opts, args = parser.parse_args()

    import logging, logging.config
    if opts.logging_conf is None:
        formatter = logging.Formatter(
            '%(asctime)s.%(msecs)03d;%(levelname)s;%(name)s;%(message)s',
            datefmt='%H:%M:%S')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
    else:
        logging.config.fileConfig(opts.logging_conf, disable_existing_loggers=False)
    logger = logging.getLogger('pydlnadms.main')
    logger.debug('Parsed opts=%r args=%r', opts, args)

    if len(args) == 0:
        #path = os.curdir
        # TODO test this on non-unix systems
        path = '/'
    elif len(args) == 1:
        path = args[0]
    else:
        parser.error('Only one path is allowed')
    path = os.path.normpath(path)

    DigitalMediaServer(opts.port, path)

if __name__ == '__main__':
    main()
