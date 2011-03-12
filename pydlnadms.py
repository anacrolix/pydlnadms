#!/usr/bin/env python3

import logging
logger = logging.getLogger('pydlnadms')
import collections, errno, functools, heapq, http.client, mimetypes
import os, pdb, platform
import select, socket, struct, sys, time, urllib.parse
from xml.etree import ElementTree as etree

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
    return tostring(scpd).encode('utf-8')

HTTP_BODY_SEPARATOR = b'\r\n' * 2
EXPIRY_FUDGE = 10
SSDP_PORT = 1900
SSDP_MCAST_ADDR = '239.255.255.250'
UPNP_ROOT_DEVICE = 'upnp:rootdevice'
UPNP_DOMAIN_NAME = 'schemas-upnp-org'
ROOT_DESC_PATH = '/rootDesc.xml'
SERVER_FIELD = '{}/{} DLNADOC/1.50 UPnP/1.0 MiniDLNA/1.0'.format(
    *platform.linux_distribution()[0:2])
ROOT_DEVICE_DEVICE_TYPE = 'urn:schemas-upnp-org:device:MediaServer:1'
ROOT_DEVICE_FRIENDLY_NAME = 'Anacrolix fucking serveR!!'
ROOT_DEVICE_MANUFACTURER = 'Matt Joiner'
ROOT_DEVICE_MODEL_NAME = 'pydlnadms 0.1'
DEVICE_DESC_SERVICE_FIELDS = 'serviceType', 'serviceId', 'SCPDURL', 'controlURL', 'eventSubURL'
CONTENT_DIRECTORY_CONTROL_URL = '/ctl/ContentDirectory'
Service = collections.namedtuple(
    'Service',
    DEVICE_DESC_SERVICE_FIELDS + ('xmlDescription',))
RESOURCE_PATH = '/res'
# flags are in hex. trailing 24 zeroes, 26 are after the space
CONTENT_FEATURES = 'DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=017000 00000000000000000000000000000000'

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
del service, domain, version

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
    return tostring(root).encode('utf-8')


class SocketWrapper:

    def __init__(self, socket_):
        self.__socket = socket_
        self.__closed = False
        try:
            self.peername = self.__socket.getpeername()
        except socket.error as exc:
            if exc.errno in [errno.ENOTCONN]:
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
        logging.debug('%r %s %s bytes from %s: %r',
            self.__socket.getsockname(),
            'peeked at' if flags & socket.MSG_PEEK else 'received',
            len(data),
            self.peername,
            data)
        return data

    def recvfrom(self, *args, **kwds):
        return self.__socket.recvfrom(*args, **kwds)

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


class SSDPSender(SocketWrapper):

    def __init__(self, hosts, master):
        #for if_addr in if_addrs:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # don't loop back multicast packets to the local sockets
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, False)
        # perhaps the local if should be the host?
        #print('mcast_if', host)
        #mreq = struct.pack('4s4s',
        #    socket.inet_aton(SSDP_MCAST_ADDR),
        #    socket.inet_aton(host))
        #s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreq)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        #s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 10)
        #s.bind(('', 0))
        super().__init__(s)
        self.master = master


class SSDPReceiver(SocketWrapper):

    def __init__(self, hosts, master):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        s.bind(('', SSDP_PORT))
        for host in hosts:
            mreq = struct.pack('4s4s',
                socket.inet_aton(SSDP_MCAST_ADDR),
                socket.inet_aton('0.0.0.0'))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        super().__init__(s)
        self.master = master

    def need_read(self):
        return True

    def need_write(self):
        return False

    def do_read(self):
        data, addr = self.recvfrom(0x1000)
        assert len(data) < 0x1000
        logging.debug('Received SSDP Request from %s: %r', addr, data)
        self.master.process_request(data, addr, self.getsockname())


class SSDP:

    logger = logging.getLogger('ssdp')

    def __init__(self, hosts, dms):
        self.sender = SSDPSender(hosts, self)
        self.receiver = SSDPReceiver(hosts, self)
        self.dms = dms
        self.ifaddrs = hosts or ('0.0.0.0',)

    @property
    def all_targets(self):
        return self.dms.all_targets

    @property
    def notify_interval(self):
        return self.dms.notify_interval

    def send_goodbye(self):
        for nt in self.dms.all_targets:
            for ifaddr in self.ifaddrs:
                buf = http_request('NOTIFY', '*', (
                    ('HOST', '{}:{:d}'.format(SSDP_MCAST_ADDR, SSDP_PORT)),
                    ('NT', nt),
                    ('USN', self.dms.usn_from_target(nt)),
                    ('NTS', 'ssdp:byebye'),))
                self.sender.sendto(buf, (SSDP_MCAST_ADDR, SSDP_PORT))
                self.logger.debug('SSDP multicasted ssdp:byebye from %s',
                    self.sender.getsockname())

    def send_notify(self):
        # TODO for each interface
        # sends should also be delayed 100ms by eventing
        for nt in self.all_targets:
            for ifaddr in self.ifaddrs:
                buf = http_request('NOTIFY', '*', (
                    ('HOST', '{}:{:d}'.format(SSDP_MCAST_ADDR, SSDP_PORT)),
                    ('CACHE-CONTROL', 'max-age={:d}'.format(
                        self.dms.notify_interval * 2 + EXPIRY_FUDGE)),
                    ('LOCATION', 'http://{}:{:d}{}'.format(
                        ifaddr,
                        self.http_address[1],
                        ROOT_DESC_PATH)),
                    ('NT', nt),
                    ('NTS', 'ssdp:alive'),
                    ('SERVER', SERVER_FIELD),
                    ('USN', self.usn_from_target(nt))))
                self.sender.sendto(buf, (SSDP_MCAST_ADDR, SSDP_PORT))
                self.logger.debug('Sent ssdp:alive: %r', buf)

    def process_request(self, data, peername, sockname):
        request = http_request_from_bytes(data)
        if request.method != 'M-SEARCH':
            return
        st = request['st']
        if st in self.all_targets:
            sts = [st]
        elif st == 'ssdp:all':
            sts = self.all_targets
        else:
            logging.debug('Ignoring M-SEARCH for %r', st)
            return
        #for sender
        for st in sts:
            self.send_msearch_reply(addr, st)

    @property
    def http_address(self):
        return self.dms.http_server.socket.getsockname()

    @property
    def usn_from_target(self):
        return self.dms.usn_from_target

    @property
    def max_age(self):
        return self.device.alive_interval * 2 + EXPIRY_FUDGE

    def send_msearch_reply(self, addr, st):
        data = http_response((
            ('CACHE-CONTROL', 'max-age={:d}'.format(self.max_age)),
            ('DATE', time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())),
            ('EXT', ''),
            ('LOCATION', 'http://{0[0]}:{0[1]:d}{1}'.format(
                self.http_address,
                ROOT_DESC_PATH)),
            ('SERVER', SERVER_FIELD),
            ('ST', st),
            ('USN', self.usn_from_target(st)),))
        self.send(data, addr)
        logging.debug('Responded to M-SEARCH from %s: %r', addr, data)

class HTTPRequest:

    __slots__ = 'method', 'path', 'protocol', 'headers'

    def __init__(self):
        self.headers = {}

    def __setitem__(self, key, value):
        self.headers[key.upper()] = value.strip()

    def __getitem__(self, key):
        return self.headers[key.upper()]

    def __contains__(self, key):
        return key.upper() in self.headers

def http_request_from_bytes(data):
    request = HTTPRequest()
    header_buf, data = data.split(b'\r\n\r\n', 1)
    assert not data
    lines = header_buf.decode('utf-8').split('\r\n')
    request.method, request.path, request.protocol = lines[0].split()
    request.path = urllib.parse.unquote(request.path)
    for h in lines[1:]:
        name, value = h.split(':', 1)
        request[name] = value
    return request

def httpify_headers(headers):
    from itertools import chain
    return '\r\n'.join(': '.join(h) for h in chain(headers, ('',)))

def http_message(first_line, headers, body):
    return (first_line + '\r\n' + httpify_headers(headers) + '\r\n').encode('utf-8') + body

def http_request(method, path, headers, body=b''):
    return http_message(' '.join((method, path, 'HTTP/1.1')), headers, body)

def http_response(headers=(), body=b'', code=200, reason=''):
    status_line = 'HTTP/1.1 {:03d} {}'.format(code, reason or http.client.responses[code])
    return http_message(status_line, list(headers) + [('Connection', 'close')], body)

def rfc1123_date():
    return time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())

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
            mimetypes.guess_type(path)[0],
            CONTENT_FEATURES))
    # TODO fix this absolute address
    res_elt.text = location + RESOURCE_PATH + urllib.parse.quote(path)
    if not isdir:
        res_elt.set('size', str(os.path.getsize(path)))
        from metadata_ff import res_data
        for attr, value in res_data(path).items():
            res_elt.set(attr, str(value))
    return etree.tostring(element)

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
    """(list of CD objects in XML, total possible elements)"""
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
        return [cd_object_xml(path, parent_id)], 1


class ResourceRequestHandler:

    def __init__(self, *, socket, request, context):
        units, range = request['range'].split('=', 1)
        assert units == 'bytes', units
        start, end = range.split('-', 1)
        self.start = int(start) if start else 0
        self.end = int(end) + 1 if end else None
        del start, end, units, range
        self.path = request.path[len(RESOURCE_PATH):]
        self.file = open(self.path, 'r+b')
        size = os.fstat(self.file.fileno()).st_size
        if self.end is None:
            # TODO: do we have to determine the end of the stream?
            self.end = size
            #pass
        else:
            self.end = min(self.end, size)
        self.file.seek(self.start)
        self.socket = socket
        headers = [
            ('Server', SERVER_FIELD),
            ('Date', rfc1123_date()),
            ('Ext', ''),
            ('transferMode.dlna.org', 'Streaming'),
            ('Content-Type', mimetypes.guess_type(self.path)[0]),
            # the resource is byte-seekable only and not transcoded
            ('contentFeatures.dlna.org', CONTENT_FEATURES),
            ('Content-Range', 'bytes {:d}-{}/{:d}'.format(
                self.start,
                '' if self.end is None else self.end - 1,
                size)),
            # TODO: wtf does this mean?
            ('realTimeInfo.dlna.org', 'DLNA.ORG_TLAG=*'),
            ('Accept-Ranges', 'bytes'),]
        if self.end is None:
            headers.append(('Connection', 'close'))
        else:
            headers.append(('Content-Length', str(self.end - self.start)))
        self.buffer = http_response(headers, code=206)

    def __repr__(self):
        return '<{} path={}, range={}-{}, len(buffer)={}>'.format(
            self.__class__.__name__,
            self.path,
            self.start, self.end,
            len(self.buffer))

    def on_done(self):
        if self.end is None or self.file.tell() != self.end or self.buffer:
            self.socket.close()

    def need_read(self):
        return False

    def need_write(self):
        return self.buffer or self.end is None or self.file.tell() < self.end

    def do_write(self):
        if not self.buffer:
            bufsize = 0x80000 # 512K
            if self.end is not None:
                bufsize = min(bufsize, self.end - self.file.tell())
            self.buffer = self.file.read(bufsize)
            if not self.buffer:
                return False
        if self.buffer:
            self.buffer = self.buffer[self.socket.send(self.buffer):]
        return self.need_write()


class SendBufferRequestHandler:

    def __init__(self, buffer, *, socket, request, context):
        self.socket = socket
        self.buffer = buffer

    def on_done(self):
        return len(self.buffer) == 0

    def need_read(self):
        return False

    def need_write(self):
        return self.buffer

    def do_write(self):
        self.buffer = self.buffer[self.socket.send(self.buffer):]
        return self.need_write()


class SoapRequestHandler:

    def __init__(self, *, socket, request, context):
        sa_value = request['soapaction']
        assert sa_value[0] == '"' and sa_value[-1] == '"', sa_value
        self.service_type, self.action = sa_value[1:-1].rsplit('#', 1)
        self.content_length = int(request['content-length'])
        self.in_buf = b''
        self.out_buf = b''
        self.socket = socket
        self.context = context
        self.request = request

    def on_done(self):
        if self.need_read() or self.need_write():
            self.socket.close()

    def need_read(self):
        return len(self.in_buf) != self.content_length

    def need_write(self):
        return self.out_buf

    def do_read(self):
        data = self.socket.recv(self.content_length - len(self.in_buf))
        if not data:
            return False
        self.in_buf += data
        del data
        if len(self.in_buf) != self.content_length:
            return True
        # we're already looking at the envelope, perhaps I should wrap this
        # with a Document so that absolute lookup is done instead? TODO
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
            assert key not in in_args
            in_args[key] = value
        out_args = getattr(self, 'soap_' + self.action)(**in_args)
        response_body = soap_action_response(
            self.service_type,
            self.action, out_args.items()).encode('utf-8')
        self.out_buf += http_response([
            ('CONTENT-LENGTH', str(len(response_body))),
            ('CONTENT-TYPE', 'text/xml; charset="utf-8"'),
            ('DATE', rfc1123_date()),
            ('EXT', ''),
            ('SERVER', SERVER_FIELD)], response_body)
        return True

    def do_write(self):
        self.out_buf = self.out_buf[self.socket.send(self.out_buf):]
        return len(self.out_buf) != 0

    def soap_Browse(self, **soap_args):
        from xml.sax.saxutils import escape
        result, total_matches = cd_browse_result(
            self.context.path,
            'http://' + self.request['host'],
            **soap_args)
        return dict(
                Result=escape(didl_lite(''.join(result))),
                NumberReturned=len(result),
                Totalmatches=total_matches,
                #('UpdateID', 10)],
            )

    def soap_GetSortCapabilities(self, **soap_args):
        return {'SortCaps': 'dc:title'}

class SoapAction: pass

class HTTPConnection:

    logger = logging.getLogger('httpconn')

    def __init__(self, socket, dms, pollmap):
        self.pollmap = pollmap
        self.buffer = b''
        self.dms = dms
        self.handler = None
        self._socket = socket

    def close(self):
        self._socket.close()
        self.pollmap.remove(self)
        self.handler = None

    def recv(self, *args, **kwargs):
        return self._socket.recv(*args, **kwargs)

    def send(self, *args, **kwargs):
        return self._socket.send(*args, **kwargs)

    def fileno(self):
        return self._socket.fileno()

    def need_read(self):
        return self.handler is None or self.handler.need_read()

    def need_write(self):
        return self.handler is not None and self.handler.need_write()

    def do_write(self):
        try:
            notdone = self.handler.do_write()
        except socket.error as exc:
            if exc.errno not in [errno.ENOTCONN]:
                raise
        else:
            if notdone:
                return
        self.handler_done()

    def handler_done(self):
        #self.handler.on_done()
        self.handler = None
        if 'connection' in self.request and \
                self.request['connection'].lower() == 'close':
            pass
        self.close()
        self.request = None

    def do_read(self):
        if self.handler is None:
            peek_data = self.recv(0x1000, socket.MSG_PEEK)
            index = (self.buffer + peek_data).find(HTTP_BODY_SEPARATOR)
            assert index >= -1, index
            if index == -1:
                bufsize = len(peek_data)
            else:
                bufsize = index - len(self.buffer) + len(HTTP_BODY_SEPARATOR)
            assert bufsize <= len(peek_data), (bufsize, len(peek_data))
            data = self.recv(bufsize)
            assert data == peek_data[:bufsize]
            if data:
                self.buffer += data
                del data
                if index != -1:
                    logging.debug('Complete HTTP request arrived: %r', self.buffer)
                    request = http_request_from_bytes(self.buffer)
                    self.buffer = b''
                    factory = self.handler_factory_new(request)
                    if factory is None:
                        self.close()
                    else:
                        assert self.handler is None, self.handler
                        self.handler = factory(
                            socket=self,
                            request=request,
                            context=self.dms)
                        self.request = request
            else:
                assert not self.buffer, self.buffer
                self.close()
        else:
            if not self.handler.do_read():
                self.handler_done()

    def handler_factory_new(self, request):
        '''Returns None if the request cannot be handled. Otherwise returns a callable that takes socket, request and done callback named arguments to handle the request.'''
        def send_buffer(buf):
            return functools.partial(SendBufferRequestHandler, buf)
        def soap_action():
            return SoapRequestHandler
        def send_description(desc):
            return functools.partial(
                SendBufferRequestHandler,
                buffer=http_response([
                        ('CONTENT-LENGTH', str(len(desc))),
                        ('CONTENT-TYPE', 'text/xml'),
                        ('DATE', rfc1123_date())
                    ], desc))
        def send_error(code):
            return send_buffer(http_response(code=code))
        if request.method in ['GET']:
            if request.path == ROOT_DESC_PATH:
                return send_description(self.dms.device_desc)
            for service in SERVICE_LIST:
                if request.path == service.SCPDURL:
                    return self.handler_from_description(service.xmlDescription)
            if request.path.startswith(RESOURCE_PATH):
                return ResourceRequestHandler
        elif request.method in ['POST']:
            if request.path in (
                    service.controlURL for service in SERVICE_LIST):
                return soap_action()
            return None
        elif request.method in ['SUBSCRIBE']:
            return None
        assert False, (request.method, request.path)

    def __str__(self):
        return '<{} handler={}, buffer={!r}>'.format(
            self.__class__.__name__,
            self.handler,
            self.buffer,)

class HTTPServer:

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
                logging.info('HTTP server listening on %s', self.socket.getsockname())
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
        logging.debug('Accepted connection from %s', addr)
        self.master.on_server_accept(sock)


class DMS:

    def __init__(self, hosts, port, path):
        self.ssdp = SSDP(hosts, self)
        # there is much more to it than this
        self.device_uuid = 'uuid:deadbeef-0000-0000-0000-0000000b00b5'
        self.notify_interval = 895
        self.device_desc = make_device_desc(self.device_uuid)
        self.http_server = HTTPServer(port, self)
        self.http_conns = []
        self.events = []
        self.path = path
        self.add_event(0, self.ssdp.send_goodbye)
        self.add_event(1, self.advertise)
        while True:
            channels = [self.http_server] + [self.ssdp.receiver] + self.http_conns
            while True:
                if self.events:
                    timeout = self.events[0][0] - time.time()
                    if timeout >= 0:
                        break
                    heapq.heappop(self.events)[1]()
                else:
                    timeout = None
                    break
                del timeout
            r = [c for c in channels if c.need_read()]
            w = [c for c in channels if c.need_write()]
            for c in channels:
                if c not in r and c not in w:
                    assert False, c
                    self.http_conns.remove(c)
            logging.debug('Polling with timeout: %s', timeout)
            r, w, x = select.select(r, w, r + w, timeout)
            assert not x, x
            if not any([r, w, x]):
                # why should this happen? signal?
                logging.debug('Select returned no events')
            else:
                for channel in r:
                    logging.debug('Read event occurred: %s', channel)
                for channel in w:
                    logging.debug('Write event occurred: %s', channel)
            for channel in r:
                channel.do_read()
            for channel in w:
                #if channel in self.http_conns:
                #pdb.set_trace()
                channel.do_write()

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
    logging.basicConfig(stream=sys.stderr, level=0)
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option('-a', '--address', action='append', default=[],
        help='notify from ADDRESS')
    #parser.add_option('-i', '--interface', action='append',
    #    help='listen on INTERFACE')
    parser.add_option('-p', '--port', type='int', default=1337,
        help='media server listen PORT')
    opts, args = parser.parse_args()
    print(opts, args)
    assert len(args) == 1, args
    DMS(opts.address, opts.port, os.path.normpath(args[0]))

if __name__ == '__main__':
    main()
