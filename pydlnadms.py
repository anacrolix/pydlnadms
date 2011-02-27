#!/usr/bin/env python3

import collections, heapq, logging, platform, select, socket, struct, sys, time

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
    for name, datatype in statevars:
        stateVariable = SubElement(serviceStateTable, 'stateVariable', sendEvents='no')
        SubElement(stateVariable, 'name').text = name
        SubElement(stateVariable, 'dataType').text = datatype
    return tostring(scpd).encode('utf-8')

EXPIRY_FUDGE = 10
SSDP_PORT = 1900
SSDP_MCAST_ADDR = '239.255.255.250'
UPNP_ROOT_DEVICE = 'upnp:rootdevice'
UPNP_DOMAIN_NAME = 'schemas-upnp-org'
ROOT_DESC_PATH = '/rootDesc.xml'
SERVER_FIELD = '{}/{} DLNADOC/1.50 UPnP/1.0 MiniDLNA/1.0'.format(
    *platform.linux_distribution()[0:2])
ROOT_DEVICE = 'urn:schemas-upnp-org:device:MediaServer:1'
DEVICE_DESC_SERVICE_FIELDS = 'serviceType', 'serviceId', 'SCPDURL', 'controlURL', 'eventSubURL'
CONTENT_DIRECTORY_CONTROL_URL = '/ctl/ContentDirectory'
Service = collections.namedtuple(
    'Service',
    DEVICE_DESC_SERVICE_FIELDS + ('xmlDescription',))

SERVICE_LIST = []
for service, domain, version, actions, statevars in [
        ('ContentDirectory', None, 1, [
            ('Browse', [
                ('ObjectID', 'in', 'A_ARG_TYPE_ObjectID')])], [
            ('A_ARG_TYPE_ObjectID', 'string')]),
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
    SubElement(device, 'deviceType').text = ROOT_DEVICE
    SubElement(device, 'friendlyName').text = 'Hello World!'
    SubElement(device, 'manufacturer').text = 'Matt Joiner'
    SubElement(device, 'modelName').text = 'pydlnadms 0.1'
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
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, False)
        # perhaps the local if should be the host?
        mreq = struct.pack('II', socket.INADDR_ANY, socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreq)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
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
        mreq = struct.pack('4sI', socket.inet_aton(SSDP_MCAST_ADDR), socket.INADDR_ANY)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
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

def soap_action_response(action_name, arguments):
    return '''<?xml version="1.0"?>
<s:Envelope
xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:{actionName}Response xmlns:u="urn:schemas-upnp-org:service:serviceType:v">
{argumentXML}
</u:{actionName}Response>
</s:Body>
</s:Envelope>'''.format(actionName=action_name, argumentXML='\n'.join(['<{argumentName}>{value}</{argumentName}>'.format(argumentName=name, value=value) for name, value in arguments]))

#def didl_lite(

class HTTPConnection:

    def __init__(self, socket, root_device):
        self.socket = socket
        self.buffer = b''
        self.root_device = root_device
        self.closed = False

    def send_description(self, desc):
        data = http_response((
                ('CONTENT-LENGTH', str(len(desc))),
                ('CONTENT-TYPE', 'text/xml'),
                ('DATE', rfc1123_date()),
            ), desc)
        sent = self.socket.send(data)
        assert sent == len(data)
        logging.debug('Sent description %s->%s: %r', self.socket.getsockname(), self.socket.getpeername(), data)

    def close(self):
        peername = self.socket.getpeername()
        self.socket.close()
        self.closed = True
        logging.debug('HTTP connection with %s was closed', peername)

    def browse_action(self):
        # omfg WHAT THE FUCK IS 'DUBLIN CORE' SMOKING?
        pass

    def on_read_event(self):
        data = self.socket.recv(0x1000)
        if not data:
            logging.debug('HTTP connection with %s closed by peer',
                self.socket.getpeername())
            self.socket.close()
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
                if soap_action.action == 'GetSortCapabilities':
                    self.close()
                    return
                elif soap_action.action == 'Browse':
                    self.browse_action()
                    return
        self.close()

    def fileno(self):
        return self.socket.fileno()

class HTTPServer:

    def __init__(self, master):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        # TODO allow binding to specific interfaces
        self.socket.bind(('', 8200))
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
        self.ssdp = SSDP('192.168.24.9', self)
        # there is much more to it than this
        self.device_uuid = 'uuid:deadbeef-0000-0000-0000-0000000b00b5'
        self.alive_interval = 10
        self.device_desc = make_device_desc(self.device_uuid)
        self.ssdp.send_goodbye()
        self.http_server = HTTPServer(self)
        self.http_conns = []
        self.events = [(0, self.advertise)]
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
        yield ROOT_DEVICE
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
