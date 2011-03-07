#!/usr/bin/env python3

import collections, functools, heapq, http.client, logging, mimetypes
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
CONTENT_DIRECTORY_ROOT = os.path.normpath('/media/data/towatch')
RESOURCE_PATH = '/res'

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
        ('X_MS_MediaReceiverRegistrar', 'microsoft.com', 1, (), ()),]:
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

    def __init__(self, socket):
        self.__socket = socket
        self.__closed = False

    def send(self, data):
        sent = self.__socket.send(data)
        fmt = 'Sent %s bytes from %s to %s'
        args = [sent, self.__socket.getsockname(), self.__socket.getpeername()]
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
            self.__socket.getpeername(),
            data)
        return data

    def fileno(self):
        return self.__socket.fileno()

    def close(self):
        assert not self.__closed
        sockname = self.__socket.getsockname()
        peername = self.__socket.getpeername()
        self.__socket.close()
        logging.debug('Closed socket: %s', (sockname, peername))
        self.__closed = True

    def getsockname(self):
        return self.__socket.getsockname()

    def getpeername(self):
        return self.__socket.getpeername()

    #def __getattr__(self, name):
    #    return getattr(self.__socket, name)


class SSDPSender(SocketWrapper):

    def __init__(self, host, master):
        #for if_addr in if_addrs:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # don't loop back multicast packets to the local sockets
        #s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, False)
        # perhaps the local if should be the host?
        mreq = struct.pack('II', socket.INADDR_ANY, socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreq)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 10)
        s.bind((host, 0))
        super().__init__(s)
        self.master = master

    def fileno(self):
        return self.socket.fileno()


class SSDPReceiver:

    def __init__(self, hosts, master):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        s.bind((hosts[0], SSDP_PORT))
        mreq = struct.pack('4sI', socket.inet_aton(SSDP_MCAST_ADDR),
            socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.socket = s
        self.master = master

    def fileno(self):
        return self.socket.fileno()

    def need_read(self):
        return True

    def need_write(self):
        return False

    def do_read(self):
        data, addr = self.socket.recvfrom(0x1000)
        assert len(data) < 0x1000
        logging.debug('Received SSDP Request from %s: %r', addr, data)
        self.master.process_request(data, addr)

class SSDP:

    def __init__(self, hosts, dms):
        self.senders = []
        for host in hosts:
            self.senders.append(SSDPSender(host, self))
        self.receiver = SSDPReceiver(hosts, self)
        self.dms = dms

    @property
    def all_targets(self):
        return self.dms.all_targets

    @property
    def notify_interval(self):
        return self.dms.notify_interval

    def send_goodbye(self):
        for nt in self.dms.all_targets:
            for sender in self.senders:
                buf = http_request('NOTIFY', '*', (
                    ('HOST', '{}:{:d}'.format(SSDP_MCAST_ADDR, SSDP_PORT)),
                    ('NT', nt),
                    ('USN', self.dms.usn_from_target(nt)),
                    ('NTS', 'ssdp:byebye'),))
                sender.sendto(buf, (SSDP_MCAST_ADDR, SSDP_PORT))
                logging.debug('SSDP multicasted ssdp:byebye from %s: %r',
                    sender.getsockname(), buf)

    def send_notify(self):
        # TODO for each interface
        # sends should also be delayed 100ms by eventing
        for nt in self.all_targets:
            for sender in self.senders:
                buf = http_request('NOTIFY', '*', (
                    ('HOST', '{}:{:d}'.format(SSDP_MCAST_ADDR, SSDP_PORT)),
                    ('CACHE-CONTROL', 'max-age={:d}'.format(
                        self.dms.notify_interval * 2 + EXPIRY_FUDGE)),
                    ('LOCATION', 'http://{0[0]}:{0[1]:d}{1}'.format(
                        self.http_address, ROOT_DESC_PATH)),
                    ('NT', nt),
                    ('NTS', 'ssdp:alive'),
                    ('SERVER', SERVER_FIELD),
                    ('USN', self.usn_from_target(nt))))
                sender.sendto(buf, (SSDP_MCAST_ADDR, SSDP_PORT))
                logging.debug('Sent ssdp:alive: %r', buf)

    def process_request(self, data, addr):
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
    return http_message(status_line, headers, body)

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

def cd_object_xml(path, parent_id):
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
        protocolInfo='http-get:*:{}:DLNA.ORG_OP=01;DLNA.ORG_CI=0'.format(
            mimetypes.guess_type(path)[0]),)
    # TODO fix this absolute address
    res_elt.text = LOCATION + RESOURCE_PATH + urllib.parse.quote(path)
    if not isdir:
        res_elt.set('size', str(os.path.getsize(path)))
    return etree.tostring(element)

def path_to_object_id(path):
    # TODO prevent escaping root directory
    path = os.path.normpath(path)
    if path == CONTENT_DIRECTORY_ROOT:
        return '0'
    else:
        return path

def object_id_to_path(object_id):
    if object_id == '0':
        return CONTENT_DIRECTORY_ROOT
    else:
        return object_id

def cd_browse_result(**soap_args):
    """(list of CD objects in XML, total possible elements)"""
    path = object_id_to_path(soap_args['ObjectID'])
    if soap_args['BrowseFlag'] == 'BrowseDirectChildren':
        entries = os.listdir(path)
        start = int(soap_args['StartingIndex'])
        count = int(soap_args['RequestedCount'])
        end = start + count if count else None
        elements = []
        for entry in entries[start:end]:
            elements.append(cd_object_xml(
                os.path.join(path, entry),
                soap_args['ObjectID']))
        return elements, len(entries)
    else:
        parent_id = path_to_object_id(os.path.normpath(os.path.split(path)[0]))
        return [cd_object_xml(path, parent_id)], 1


class ResourceRequestHandler:

    def __init__(self, *, socket, request, done):
        #pdb.set_trace()
        units, range = request['range'].split('=', 1)
        assert units == 'bytes'
        start, end = range.split('-', 1)
        self.start = int(start) if start else 0
        self.end = int(end) if end else None
        del start, end, units, range
        path = request.path[len(RESOURCE_PATH):]
        self.file = open(path, 'r+b')
        self.file.seek(self.start)
        self.done = done
        self.socket = socket
        headers = [
            ('Server', SERVER_FIELD),
            ('Date', rfc1123_date()),
            ('Ext', ''),
            ('transferMode.dlna.org', 'Streaming'),
            ('Content-Type', mimetypes.guess_type(path)[0]),
            ('contentFeatures.dlna.org', 'DLNA.ORG_OP=01;DLNA.ORG_CI=0')]
        if self.end is not None:
            headers.append(('CONTENT-LENGTH', str(self.end - self.start)))
        self.buffer = http_response(headers)

    def need_read(self):
        return True

    def need_write(self):
        return self.buffer or self.file.tell() != self.end

    def do_write(self):
        #pdb.set_trace()
        if not self.buffer:
            if self.end is None:
                bufsize = 0x20000
            else:
                bufsize = self.end - self.file.tell()
            self.buffer += self.file.read(bufsize)
            if not self.buffer:
                self.done()
        try:
            self.buffer = self.buffer[self.socket.send(self.buffer):]
        except socket.error as exc:
            if exc.errno == errno.EPIPE:
                self.done(die=True)


class SendBufferRequestHandler:

    def __init__(self, buffer, *, socket, request, done):
        self.socket = socket
        self.buffer = buffer
        self.done = done

    def need_read(self):
        return False

    def need_write(self):
        return self.buffer

    def do_write(self):
        self.buffer = self.buffer[self.socket.send(self.buffer):]
        if not self.buffer:
            self.done()


class SoapRequestHandler:

    def __init__(self, *, socket, request, done):
        sa_value = request['soapaction']
        assert sa_value[0] == '"' and sa_value[-1] == '"', sa_value
        self.service_type, self.action = sa_value[1:-1].rsplit('#', 1)
        self.content_length = int(request['content-length'])
        self.in_buf = b''
        self.out_buf = b''
        self.socket = socket
        self.done = done

    def need_read(self):
        return len(self.in_buf) != self.content_length

    def need_write(self):
        return self.out_buf

    def do_read(self):
        data = self.socket.recv(self.content_length - len(self.in_buf))
        if not data:
            self.close()
        self.in_buf += data
        del data
        if len(self.in_buf) == self.content_length:
            # we're already looking at the envelope, perhaps I should wrap this with
            # a Document so that absolute lookup is done instead? TODO
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

    def do_write(self):
        self.out_buf = self.out_buf[self.socket.send(self.out_buf):]
        if not self.out_buf:
            assert len(self.in_buf) == self.content_length
            self.done()

    def soap_Browse(self, **soap_args):
        from xml.sax.saxutils import escape
        result, total_matches = cd_browse_result(**soap_args)
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

    def __init__(self, socket, dms, pollmap):
        self.pollmap = pollmap
        self.buffer = b''
        self.dms = dms
        self.handler = None
        self._socket = socket

    def close(self):
        self._socket.close()
        self.pollmap.remove(self)

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
        self.handler.do_write()

    def handler_done(self, die=False):
        self.handler = None
        if die or 'connection' in self.request and \
                self.request['connection'].lower() == 'close':
            self.close()
        self.request = None

    def do_read(self):
        if self.handler is None:
            peek_data = self.recv(0x1000, socket.MSG_PEEK)
            index = (self.buffer + peek_data).find(HTTP_BODY_SEPARATOR)
            assert index >= -1
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
                    logging.debug('Processing completed HTTP request: %r', self.buffer)
                    request = http_request_from_bytes(self.buffer)
                    self.buffer = b''
                    factory = self.handler_factory_new(request)
                    if factory is None:
                        self.close()
                    else:
                        self.handler = factory(
                            socket=self,
                            request=request,
                            done=self.handler_done)
                        self.request = request
            else:
                assert not self.buffer, self.buffer
                self.close()
        else:
            self.handler.do_read()

    def handler_factory_new(self, request):
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
        if request.method in ['GET', 'HEAD']:
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

    def __init__(self, hosts, port):
        self.ssdp = SSDP(hosts, self)
        # there is much more to it than this
        self.device_uuid = 'uuid:deadbeef-0000-0000-0000-0000000b00b5'
        self.notify_interval = 895
        self.device_desc = make_device_desc(self.device_uuid)
        self.http_server = HTTPServer(port, self)
        self.http_conns = []
        self.events = []
        self.add_event(0, self.ssdp.send_goodbye)
        self.add_event(1, self.advertise)
        while True:
            channels = [self.http_server, self.ssdp.receiver] + self.http_conns
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
                    self.http_conns.remove(c)
            logging.debug('Polling with timeout: %s', timeout)
            r, w, x = select.select(r, w, r + w, timeout)
            assert not x, x
            if not any([r, w, x]):
                # why should this happen? signal?
                logging.debug('Select returned no events')
            for channel in r:
                channel.do_read()
            for channel in w:
                channel.do_write()

    def add_event(self, delay, callback):
        heapq.heappush(self.events, (time.time() + delay, callback))

    def advertise(self):
        self.ssdp.send_notify()
        self.add_event(self.notify_interval, self.advertise)

    def on_server_accept(self, sock):
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
    parser.add_option('-a', '--attach', action='append',
        help='listen on ADDRESS')
    #parser.add_option('-i', '--interface', action='append',
    #    help='listen on INTERFACE')
    parser.add_option('-p', '--port', type='int', default=1337,
        help='media server listen PORT')
    opts, args = parser.parse_args()
    DMS(opts.attach, opts.port)

if __name__ == '__main__':
    main()
