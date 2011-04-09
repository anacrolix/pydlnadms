#!/usr/bin/env python3
# filetype=python3

import collections
from xml.etree import ElementTree as etree
import fcntl
import getpass
import heapq
import logging # deleted at end of module
import os
import os.path
import platform
import pprint
import select
import socket
import subprocess
import sys
import time
import urllib.parse


logger = logging.getLogger()


# fix xml.etree.ElementTree.tostring for python < 3.2

_etree_tostring_original = etree.tostring

def _etree_tostring_wrapper(*args, **kwargs):
    if kwargs['encoding'] == 'unicode':
        del kwargs['encoding']
    return _etree_tostring_original(*args, **kwargs)

if sys.version_info.major <= 3 and sys.version_info.minor < 2:
    etree.tostring = _etree_tostring_wrapper


EXPIRY_FUDGE = 10
UPNP_ROOT_DEVICE = 'upnp:rootdevice'
UPNP_DOMAIN_NAME = 'schemas-upnp-org'
ROOT_DESC_PATH = '/rootDesc.xml'
SERVER_FIELD = '{}/{} DLNADOC/1.50 UPnP/1.0 MiniDLNA/1.0'.format(
    *platform.linux_distribution()[0:2])
ROOT_DEVICE_DEVICE_TYPE = 'urn:schemas-upnp-org:device:MediaServer:1'
ROOT_DEVICE_FRIENDLY_NAME = 'pydlnadms: {!r} on {!r}'.format(
    getpass.getuser(), platform.node())

ROOT_DEVICE_MANUFACTURER = 'Matt Joiner'
ROOT_DEVICE_MODEL_NAME = 'pydlnadms 0.1'
DEVICE_DESC_SERVICE_FIELDS = 'serviceType', 'serviceId', 'SCPDURL', 'controlURL', 'eventSubURL'
CONTENT_DIRECTORY_CONTROL_URL = '/ctl/ContentDirectory'
Service = collections.namedtuple(
    'Service',
    DEVICE_DESC_SERVICE_FIELDS + ('xmlDescription',))
RESOURCE_PATH = '/res'
# flags are in hex. trailing 24 zeroes, 26 are after the space
# "DLNA.ORG_OP=" time-seek-range-supp bytes-range-header-supp
CONTENT_FEATURES = 'DLNA.ORG_OP=10;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=017000 00000000000000000000000000000000'
SSDP_PORT = 1900
SSDP_MCAST_ADDR = '239.255.255.250'

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


class HTTPResponse:

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


class RequestHandlerContext:
    __slots__ = 'socket', 'on_done', 'request', 'dms'


class HTTPConnection:

    __slots__ = 'pollmap', 'buffer', 'dms', 'handler', '_socket'

    logger = logging.getLogger('http.conn')

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
            if exc.errno not in [errno.ENOTCONN, errno.EPIPE, errno.ECONNRESET]:
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

            try:
                request = HTTPRequest.from_bytes(self.buffer)
            except ValueError:
                self.logger.exception('Failed to parse HTTP request')
                self.close()
                return
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
        def send_buffer(buf):
            return functools.partial(SendBuffer, buf)
        def soap_action():
            return Soap
        def send_description(desc):
            import functools
            return functools.partial(
                SendBuffer,
                buffer=HTTPResponse([
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
            if request.path == RESOURCE_PATH:
                return ResourceRequestHandler
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

    def __repr__(self):
        return '<{}.{} socket={} master={}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            self.socket,
            self.master)


def guess_mimetype(path):
    return 'video/mpeg'
    from mimetypes import guess_type
    type = guess_type(path)[0]
    if type is None:
        type = 'application/octet-stream'
    if type == 'video/MP2T':
        type = 'video/mpeg'
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


class TranscodeResource:

    def __init__(self, path, start, end):
        args = ['ffmpeg', '-i', path]
        if start:
            args += ['-ss', start]
        if end:
            args += ['-t', end]
        args += [
            '-vbsf', 'h264_mp4toannexb',
            '-vcodec', 'copy',
            '-acodec', 'copy',
            '-scodec', 'copy',
            '-f', 'mpegts',
            '-y', '/dev/stdout']
        self.child = subprocess.Popen(
            args,
            stdin=open(os.devnull, 'rb'),
            stdout=subprocess.PIPE,)
            #stderr=subprocess.PIPE)
        def set_non_blocking(fd):
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK|flags)
        #set_non_blocking(self.child.stderr)
        #set_non_blocking(self.child.stdout)

    def read(self, count):
        #stderr_output = self.child.stderr.read()
        #logger.debug('Got %d bytes from stderr', len(stderr_output or ''))
        #if stderr_output:
            #logger.info('Transcoder diagnostic: %s', stderr_output)
        output = self.child.stdout.read(count)
        logger.debug('Got %d bytes from stdout', len(output or ''))
        if not output:
            self.child.poll()
        return output


class ResourceRequestHandler:

    def __init__(self, context):
        request = context.request
        path = request.query['path'][-1]
        response_headers = [
            ('Server', SERVER_FIELD),
            ('Date', rfc1123_date()),
            ('Ext', ''),
            ('transferMode.dlna.org', 'Streaming'),
            ('contentFeatures.dlna.org', CONTENT_FEATURES),
            # TODO: wtf does this mean?
            ('realTimeInfo.dlna.org', 'DLNA.ORG_TLAG=*'),
            ('Connnection', 'close')]
        if 'range' in request:
            units, range = request['range'].split('=', 1)
            assert units == 'bytes', units
            start, end = range.split('-', 1)
            start = int(start) if start else 0
            end = int(end) + 1 if end else None
            resource = FileResource(path, start, end)
            response_headers.extend([(
                    'Content-Range',
                    'bytes={:d}-{}/{:d}'.format(
                        start,
                        '' if end is None else self.end - 1,
                        resource.size)
                ), ('Content-Type', guess_mimetype(path)),
                ('Accept-Ranges', 'bytes')])
            if not end is None:
                response_headers.append(
                    ('Content-Length', str(end - start)))
            del units, range, start, end
        elif 'timeseekrange.dlna.org' in request:
            units, range = request['timeseekrange.dlna.org'].split('=', 1)
            start, end = range.split('-', 1)
            resource = TranscodeResource(path, start, end)
            response_headers.extend([(
                    'TimeSeekRange.dlna.org',
                    request['timeseekrange.dlna.org'] + '/*'
                ), ('Content-type', 'video/mpeg')])
            del units, range, start, end
        else:
            resource = TranscodeResource(path, '0', None)
        self.resource = resource
        self.on_done = context.on_done
        self.socket = context.socket
        self.buffer = HTTPResponse(response_headers, code=206).to_bytes()

    def __repr__(self):
        return '<{} len(buffer)={} resource={}>'.format(
            self.__class__.__name__,
            len(self.buffer),
            self.resource)

    def need_read(self):
        return False

    def need_write(self):
        return True

    def do_write(self):
        if not self.buffer:
            self.buffer = self.resource.read(0x20000)
            if not self.buffer:
                self.on_done(close=True)
                return
        self.buffer = self.buffer[self.socket.send(self.buffer):]


class SendBuffer:

    def __init__(self, buffer, context):
        self.socket = context.socket
        self.buffer = buffer
        self.on_done = context.on_done

    def need_read(self):
        return False

    def need_write(self):
        return self.buffer

    def do_write(self):
        self.buffer = self.buffer[self.socket.send(self.buffer):]
        if not self.buffer:
            self.on_done()


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

def cd_object_xml(path, location, parent_id):
    '''Returns a DIDL response object XML snippet'''
    from xml.etree import ElementTree as etree
    import os, os.path, urllib.parse
    isdir = os.path.isdir(path)
    element = etree.Element(
        'container' if isdir else 'item',
        id=path, parentID=parent_id, restricted='1')
    if isdir:
        element.set('childCount', str(len(os.listdir(path))))
    etree.SubElement(element, 'dc:title').text = os.path.basename(path)
    class_elt = etree.SubElement(element, 'upnp:class')
    if isdir:
        class_elt.text = 'object.container.storageFolder'
    else:
        class_elt.text = 'object.item.videoItem'
    res_elt = etree.SubElement(element, 'res',
        protocolInfo='http-get:*:{}:{}'.format(
            guess_mimetype(path),
            CONTENT_FEATURES))
    scheme, netloc = location
    res_elt.text = urllib.parse.urlunsplit((
        scheme,
        netloc,
        RESOURCE_PATH,
        urllib.parse.urlencode([('path', path)]),
        None))
    if not isdir:
        res_elt.set('size', str(os.path.getsize(path)))
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

def object_id_to_path(root_path, object_id):
    if object_id == '0':
        return root_path
    else:
        return object_id

def cd_browse_result(root_path, location, **soap_args):
    '''(list of CD objects in XML, total possible elements)'''
    import os, os.path
    path = object_id_to_path(root_path, soap_args['ObjectID'])
    if soap_args['BrowseFlag'] == 'BrowseDirectChildren':
        entries = sorted(os.listdir(path))
        start = int(soap_args['StartingIndex'])
        count = int(soap_args['RequestedCount'])
        end = start + count if count else None
        elements = []
        for entry in entries[start:end]:
            elements.append(cd_object_xml(
                os.path.join(path, entry),
                location,
                soap_args['ObjectID']))
        return elements, len(entries)
    else:
        parent_id = path_to_object_id(os.path.normpath(os.path.split(path)[0]))
        return [cd_object_xml(path, location, parent_id)], 1


class Soap:

    def __init__(self, context):
        request = context.request
        soapact = request['soapaction']
        assert soapact[0] == '"' and soapact[-1] == '"', soapact
        self.service_type, self.action = soapact[1:-1].rsplit('#', 1)
        self.content_length = int(request['content-length'])
        self.in_buf = b''
        self.out_buf = b''
        self.dms = context.dms
        self.request = request
        self.socket = context.socket
        self.on_done = context.on_done

    # TODO neatly report SOAP info
    #def __repr__(self):
        #return '<

    def need_read(self):
        return self.content_length - len(self.in_buf)

    def need_write(self):
        return self.out_buf

    def do_read(self):
        data = self.socket.recv(self.content_length - len(self.in_buf))
        if not data:
            # TODO send SOAP error response?
            logging.error('SOAP request body was not completed: %r', self.in_buf)
            self.on_done(close=True)
        self.in_buf += data
        del data

        if len(self.in_buf) != self.content_length:
            return

        # we're already looking at the envelope, perhaps I should wrap this
        # with a Document so that absolute lookup is done instead? TODO
        from xml.etree import ElementTree as etree
        soap_request = etree.fromstring(self.in_buf)
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
        self.out_buf += HTTPResponse([
            ('CONTENT-LENGTH', str(len(response_body))),
            ('CONTENT-TYPE', 'text/xml; charset="utf-8"'),
            ('DATE', rfc1123_date()),
            ('EXT', ''),
            ('SERVER', SERVER_FIELD)
        ], response_body, code=200).to_bytes()

    def do_write(self):
        self.out_buf = self.out_buf[self.socket.send(self.out_buf):]
        if not self.out_buf:
            self.on_done()

    def soap_Browse(self, **soap_args):
        from xml.sax.saxutils import escape
        result, total_matches = cd_browse_result(
            self.dms.path,
            ('http', self.request['host']),
            **soap_args)
        return dict(
                Result=escape(didl_lite(''.join(result))),
                NumberReturned=len(result),
                Totalmatches=total_matches,
                #('UpdateID', 10)],
            )

    def soap_GetSortCapabilities(self, **soap_args):
        return {'SortCaps': 'dc:title'}


class SocketWrapper:

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
        fmt = 'Sent %s bytes on %s to %s'
        args = [sent, self.sockname, self.peername]
        if sent <= 24 * 80:
            fmt += ': %r'
            args += [data[:sent]]
            self.logger.debug(fmt, *args)
        else:
            self.logger.debug(fmt, *args)
            self.logger.debug('%r', data[:sent])
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
            if ifaddr.family == AF_INET: #and not ifaddr.flags & IFF_LOOPBACK:
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
                buf = HTTPRequest('NOTIFY', '*', (
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
                self.ssdp_multicast(family, addr, buf)
        self.logger.debug('Sent SSDP alive notifications')

    def process_request(self, data, peeraddr, sockaddr):
        request = HTTPRequest.from_bytes(data)
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
        buf = HTTPResponse([
                ('CACHE-CONTROL', 'max-age={:d}'.format(self.max_age)),
                ('DATE', rfc1123_date()),
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
    serviceList = SubElement(device, 'serviceList')
    for service in SERVICE_LIST:
        service_elt = SubElement(serviceList, 'service')
        for tag in DEVICE_DESC_SERVICE_FIELDS:
            SubElement(service_elt, tag).text = getattr(service, tag)
    return tostring(root, encoding='utf-8')#.encode('utf-8')


class DigitalMediaServer:

    logger = logging.getLogger('pydlnadms')

    def __init__(self, port, path):
        self.ssdp = SSDP(self)
        # TODO there is much more to it than this
        self.device_uuid = 'uuid:deadbeef-0000-0000-0000-{:012x}'.format(
            abs(hash(ROOT_DEVICE_FRIENDLY_NAME)))
        self.logger.info('UUID is %r', self.device_uuid)
        self.notify_interval = 895
        self.device_desc = make_device_desc(self.device_uuid)
        self.http_server = Server(port, self)
        self.http_conns = []
        self.events = []
        self.path = path
        self.add_event(0, self.ssdp.send_goodbye)
        self.add_event(2, self.advertise)
        self.run()

    def run(self):
        while True:
            # execute any events who've passed their due times
            while True:
                if self.events:
                    timeout = self.events[0][0] - time.time()
                    if timeout >= 0:
                        # event not ready, so set the timeout
                        break
                    # event ready, execute it
                    heapq.heappop(self.events)[1]()
                else:
                    # no events pending, so there is no timeout
                    timeout = None
                    break
                del timeout

            channels = [self.http_server] + self.ssdp.channels + self.http_conns
            readset =  [chan for chan in channels if chan.need_read()]
            writeset = [chan for chan in channels if chan.need_write()]
            self.logger.debug('Selecting on channels:\n%s', pprint.pformat(channels))
            for chan in channels:
                assert chan in readset or chan in writeset, chan

            self.logger.debug('Polling with timeout: %s', timeout)
            readset, writeset, exptset = select.select(
                readset, writeset, channels, timeout)
            assert not exptset, exptset # never had reason to get exception yet
            if not any((readset, writeset, exptset)):
                # why should this happen? signal?
                self.logger.info('Select returned no events!')
            else:
                for chan in readset:
                    self.logger.debug('Read event occurred: %s', chan)
                for chan in writeset:
                    self.logger.debug('Write event occurred: %s', chan)
            for chan in readset:
                chan.do_read()
            for chan in writeset:
                chan.do_write()

    def add_event(self, delay, callback):
        heapq.heappush(self.events, (time.time() + delay, callback))

    def advertise(self):
        self.ssdp.send_notify()
        self.add_event(self.notify_interval, self.advertise)

    def on_server_accept(self, sock):
        sock.setblocking(False)
        self.http_conns.append(HTTPConnection(
            SocketWrapper(sock), self, self.http_conns))

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
        '--logging-conf',
        help='Path of Python logging configuration file')
    opts, args = parser.parse_args()

    import logging, logging.config
    if opts.logging_conf is None:
        formatter = logging.Formatter(
            '%(asctime)s.%(msecs)3d;%(levelname)s;%(name)s;%(message)s',
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
        path = os.curdir
    elif len(args) == 1:
        path = args[0]
    else:
        parser.error('Only one path is allowed')
    path = os.path.normpath(path)

    # import this AFTER logging config has been processed
    from pydlnadms import DigitalMediaServer
    DigitalMediaServer(opts.port, path)

del logging

if __name__ == '__main__':
    main()

#if __name__ == '__main__':
    #class Master:
        #def process_request(self, buf, peeraddr, sockaddr):
            #print(buf, peeraddr, sockaddr)
    #master = Master()
    #sr = SSDPReceiver(master)
    #while True:
        #sr.do_read()
