#!/usr/bin/env python3

from .constant import *
from .socket_wrapper import SocketWrapper

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
    #import os.path
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


import heapq, select, time

class DigitalMediaServer:

    import logging
    logger = logging.getLogger('pydlnadms')
    del logging

    def __init__(self, port, path):
        from .ssdp import SSDP
        self.ssdp = SSDP(self)
        # TODO there is much more to it than this
        self.device_uuid = 'uuid:deadbeef-0000-0000-0000-0000000b00b5'
        self.notify_interval = 895
        self.device_desc = make_device_desc(self.device_uuid)
        from .http import Server
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
        from .http import Connection
        self.http_conns.append(Connection(
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
