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
    return tostring(root)#.encode('utf-8')


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
