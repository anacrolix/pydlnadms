#!/usr/bin/env python3

import collections, heapq, logging, os, pdb, platform, select, socket, struct, \
    sys, time
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

print(SERVICE_LIST)

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


class SSDPSender:

    def __init__(self, host, master):
        #for if_addr in if_addrs:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # don't loop back multicast packets to the local sockets
        #s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, False)
        # perhaps the local if should be the host?
        #mreq = struct.pack('II', socket.INADDR_ANY, socket.INADDR_ANY)
        #s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreq)
        #s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        s.bind((host, 0))
        self.socket = s
        self.master = master

    def fileno(self):
        return self.socket.fileno()


class SSDPReceiver:

    def __init__(self, host, master):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        s.bind((host, SSDP_PORT))
        #mreq = struct.pack('4sI', socket.inet_aton(SSDP_MCAST_ADDR), socket.INADDR_ANY)
        #s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.socket = s
        self.master = master
        self.closed = False

    def fileno(self):
        return self.socket.fileno()

    def on_read_event(self):
        data, addr = self.socket.recvfrom(0x1000)
        assert len(data) < 0x1000
        logging.debug('Received SSDP Request from %s: %r', addr, data)
        self.master.process_request(data, addr)

class SSDP:

    def __init__(self, host, device):
        self.host = host
        self.sender = SSDPSender(host, self)
        self.receiver = SSDPReceiver(host, self)
        self.device = device

    @property
    def all_targets(self):
        return self.device.all_targets

    @property
    def notify_interval(self):
        return self.device.notify_interval

    def send(self, data, addr):
        self.sender.socket.sendto(data, addr)

    def send_goodbye(self):
        for nt in self.device.all_targets:
            buf = http_request('NOTIFY', '*', (
                ('HOST', '{}:{:d}'.format(SSDP_MCAST_ADDR, SSDP_PORT)),
                ('NT', nt),
                ('USN', self.device.usn_from_target(nt)),
                ('NTS', 'ssdp:byebye'),))
            self.send(buf, (SSDP_MCAST_ADDR, SSDP_PORT))
            logging.debug('Sent ssdp:byebye: %r', buf)

    def send_notify(self):
        for nt in self.all_targets:
            data = http_request('NOTIFY', '*', (
                ('HOST', '{}:{:d}'.format(SSDP_MCAST_ADDR, SSDP_PORT)),
                ('CACHE-CONTROL', 'max-age={:d}'.format(
                    self.device.alive_interval * 2 + EXPIRY_FUDGE)),
                ('LOCATION', 'http://{0[0]}:{0[1]:d}{1}'.format(
                    self.http_address, ROOT_DESC_PATH)),
                ('NT', nt),
                ('NTS', 'ssdp:alive'),
                ('SERVER', SERVER_FIELD),
                ('USN', self.usn_from_target(nt))))
            self.send(data, (SSDP_MCAST_ADDR, SSDP_PORT))
            logging.debug('Sent ssdp:alive: %r', data)

    def process_request(self, data, addr):
        lines = data.decode('utf-8').split('\r\n')
        if not lines[0].startswith('M-SEARCH'):
            return
        for line in lines[1:]:
            if line.startswith('ST:'):
                st = line[3:].strip()
        if st == 'ssdp:all':
            sts = self.all_targets
        else:
            sts = [st]
        for st in sts:
            self.send_msearch_reply(addr, st)

    @property
    def http_address(self):
        return (
            self.receiver.socket.getsockname()[0],
            self.device.http_server.socket.getsockname()[1])

    @property
    def usn_from_target(self):
        return self.device.usn_from_target

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

class SOAPActionHeader: pass

def parse_soap_action_header_value(value):
    assert value[0] == '"' and value[-1] == '"', value
    service_type, action = value[1:-1].rsplit('#', 1)
    sa = SOAPActionHeader()
    sa.service_type = service_type
    sa.action = action
    return sa

class HTTPRequest:

    __slots__ = 'method', 'path', 'protocol', 'headers'

    def __init__(self):
        self.headers = {}

    def __setitem__(self, key, value):
        self.headers[key.upper()] = value.strip()

    def __getitem__(self, key):
        return self.headers[key.upper()]

    @classmethod
    def from_bytes(cls, data):
        request = cls()
        header_buf, data = data.split(b'\r\n\r\n', 1)
        lines = header_buf.decode('utf-8').split('\r\n')
        request.method, request.path, request.protocol = lines[0].split()
        for h in lines[1:]:
            name, value = h.split(':', 1)
            request[name] = value
        return request, data

def httpify_headers(headers):
    from itertools import chain
    return '\r\n'.join(': '.join(h) for h in chain(headers, ('',)))

def http_message(first_line, headers, body):
    return (first_line + '\r\n' + httpify_headers(headers) + '\r\n').encode('utf-8') + body

def http_request(method, path, headers, body=b''):
    return http_message(' '.join((method, path, 'HTTP/1.1')), headers, body)

def http_response(headers, body=b''):
    return http_message('HTTP/1.1 200 OK', headers, body)

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

#class CDPathObject:

    #def __init__(self, id, parent_id, path):
        #self.parent_id = parent_id
        #self.path = path

    #@property
    #def xml(self):
        #isdir = os.path.isdir(self.path)
        #element = etree.Element(
            #'container' if isdir else 'item',
            #id=self.id,
            #parentID=self.parent_id,
            #restricted='1')
        #if isdir:
            #element.set('childCount', str(len(os.listdir(self.path))))
        #SubElement(element, 'dc:title').text = os.path.basename(self.path)
        #class_elt = SubElement(element, 'upnp:class')
        #if isdir:
            #class_elt.text = 'object.container.storageFolder'
        #else:
            #class_elt.text = 'object.item.videoItem'
        #return etree.tostring(element)

#class Objects:

    #def __init__(self):
        #self.id_to_object = {}
        #self.path_to_id = {}
        #self.next_id = 0

    #def add_path(self, path):
        #self.map[self.next_id] = PathObject(path)

    #def by_path(self, path):

#objects = Objects()
#objects.add_path('/media/data/towatch')

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
            protocolInfo='http-get:*:video/avi:DLNA.ORG_OP=01;DLNA.ORG_CI=0'
        ).text = 'http://192.168.24.9/res' + path
    return etree.tostring(element)

def cd_browse_result(**soap_args):
    """(list of CD objects in XML, total possible elements)"""
    path = soap_args['ObjectID']
    if path == '0':
        path = '/media/data/towatch'
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
        assert False, soap_args['BrowseFlag']

class HTTPConnection:

    def __init__(self, socket, root_device):
        self.socket = socket
        self.buffer = b''
        self.root_device = root_device
        self.closed = False

    def send(self, data):
        sent = self.socket.send(data)
        assert sent == len(data), (sent, len(data))

    def send_description(self, desc):
        data = http_response((
                ('CONTENT-LENGTH', str(len(desc))),
                ('CONTENT-TYPE', 'text/xml'),
                ('DATE', rfc1123_date()),
            ), desc)
        self.send(data)
        logging.debug('Sent description %s->%s: %r',
            self.socket.getsockname(),
            self.socket.getpeername(),
            data)

    def close(self):
        peername = self.socket.getpeername()
        self.socket.close()
        self.closed = True
        logging.debug('HTTP connection with %s was closed', peername)

        a = '\n<container id="64" parentID="0" restricted="1" childCount="2"><dc:title>Browse Folders</dc:title><upnp:class>object.container.storageFolder</upnp:class></container><container id="1" parentID="0" restricted="1" childCount="6"><dc:title>Music</dc:title><upnp:class>object.container.storageFolder</upnp:class></container><container id="3" parentID="0" restricted="1" childCount="4"><dc:title>Pictures</dc:title><upnp:class>object.container.storageFolder</upnp:class></container><container id="2" parentID="0" restricted="1" childCount="2"><dc:title>Video</dc:title><upnp:class>object.container.storageFolder</upnp:class></container>'

    def process_soap_action(self, soap_action, soap_request):
        from xml.sax.saxutils import escape
        # we're already looking at the envelope, perhaps I should wrap this with
        # a Document so that absolute lookup is done instead? TODO
        action_elt = soap_request.find(
            '{{{s}}}Body/{{{u}}}{action}'.format(
                s='http://schemas.xmlsoap.org/soap/envelope/',
                u=soap_action.service_type,
                action=soap_action.action))
        in_arguments = {}
        for child_elt in action_elt.getchildren():
            assert not child_elt.getchildren()
            key = child_elt.tag
            value = child_elt.text
            assert key not in in_arguments
            in_arguments[key] = value
        if soap_action.action == 'Browse':
            result, total_matches = cd_browse_result(**in_arguments)
            response_body = soap_action_response(
                soap_action.service_type,
                soap_action.action, [
                    ('Result', escape(didl_lite(''.join(result)))),
                    ('NumberReturned', len(result)),
                    ('TotalMatches', total_matches)
                    #('UpdateID', 10)],
                ]).encode('utf-8')
            self.send(http_response([
                ('CONTENT-LENGTH', str(len(response_body))),
                ('CONTENT-TYPE', 'text/xml; charset="utf-8"'),
                ('DATE', rfc1123_date()),
                ('EXT', ''),
                ('SERVER', SERVER_FIELD)], response_body))
            logging.debug('Sent Browse response: %r', response_body)
        #pdb.set_trace()
        self.close()

    def on_read_event(self):
        data = self.socket.recv(0x1000)
        if not data:
            logging.debug('HTTP connection with %s closed by peer',
                self.socket.getpeername())
            self.closed = True
            return
        logging.debug('%s to %s: %r', self.socket.getpeername(), self.socket.getsockname(), data)
        self.buffer += data
        request, data = HTTPRequest.from_bytes(data)
        assert not len(data) or len(data) == int(request['content-length'])
        if request.method in ['GET', 'HEAD']:
            if request.path == ROOT_DESC_PATH:
                self.send_description(self.root_device.device_desc)
                return
            for service in SERVICE_LIST:
                if request.path == service.SCPDURL:
                    self.send_description(service.xmlDescription)
                    return
        elif request.method in ['POST']:
            if request.path in (service.controlURL for service in SERVICE_LIST):
                soap_action = parse_soap_action_header_value(request['soapaction'])
                self.process_soap_action(soap_action, etree.fromstring(data))
                return
        elif request.method in ['SUBSCRIBE']:
            self.close()
            return
        assert False, (request.method, request.path)
        self.close()

    def fileno(self):
        return self.socket.fileno()

class HTTPServer:

    def __init__(self, master):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        # TODO allow binding to specific interfaces
        port = 8200
        while True:
            try:
                self.socket.bind(('', port))
            except socket.error as exc:
                if exc.errno != 98:
                    raise
            else:
                break
            port += 1
        # TODO use the socket backlog default
        self.socket.listen(5)
        self.master = master
        self.closed = False

    def fileno(self):
        return self.socket.fileno()

    def on_read_event(self):
        sock, addr = self.socket.accept()
        logging.debug('Accepted connection from %s', addr)
        self.master.on_server_accept(sock)

class DMS:

    def __init__(self):
        logging.basicConfig(stream=sys.stderr, level=0)
        self.ssdp = SSDP('', self)
        # there is much more to it than this
        self.device_uuid = 'uuid:deadbeef-0000-0000-0000-0000000b00b5'
        self.alive_interval = 895
        self.device_desc = make_device_desc(self.device_uuid)
        self.http_server = HTTPServer(self)
        self.http_conns = []
        self.events = []
        self.add_event(0, self.ssdp.send_goodbye)
        self.add_event(1, self.advertise)
        while True:
            r = [self.http_server, self.ssdp.receiver] + self.http_conns
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
            logging.debug('Polling with timeout: %s', timeout)
            r, w, x = select.select(r, [], [], timeout)
            assert not w and not x
            if not r:
                logging.debug('Select returned no events')
            for channel in r:
                channel.on_read_event()
                if channel.closed:
                    self.http_conns.remove(channel)

    def add_event(self, delay, callback):
        heapq.heappush(self.events, (time.time() + delay, callback))

    def advertise(self):
        self.ssdp.send_notify()
        self.add_event(self.alive_interval, self.advertise)

    def on_server_accept(self, sock):
        self.http_conns.append(HTTPConnection(sock, self))

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
    DMS()

if __name__ == '__main__':
    main()
