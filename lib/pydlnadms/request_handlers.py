from .constant import *
import logging
logger = logging.getLogger('pydlnadms')
del logging

def guess_mimetype(path):
    from mimetypes import guess_type
    type = guess_type(path)[0]
    if type is None:
        type = 'application/octet-stream'
    return type
    #return 'video/x-msvideo'
    #return 'video/MP2T'


class Resource:

    def __init__(self, context):
        self.on_done = context.on_done
        request = context.request
        units, range = request['range'].split('=', 1)
        assert units == 'bytes', units
        start, end = range.split('-', 1)
        self.start = int(start) if start else 0
        self.end = int(end) + 1 if end else None
        del start, end, units, range
        self.path = request.query['path'][-1]
        try:
            self.file = open(self.path, 'rb')
        except IOError as exc:
            if exc.errno == errno.ENOENT:
                logger.exception('Error in resource request handler')
            self.on_done(close=True)
        import os
        size = os.fstat(self.file.fileno()).st_size
        if self.end is None:
            # TODO: do we have to determine the end of the stream?
            self.end = size
            #pass
        else:
            self.end = min(self.end, size)
        self.file.seek(self.start)
        self.socket = context.socket
        from . import http
        headers = [
            ('Server', SERVER_FIELD),
            ('Date', http.rfc1123_date()),
            ('Ext', ''),
            ('transferMode.dlna.org', 'Streaming'),
            ('Content-Type', guess_mimetype(self.path)),
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
        self.buffer = http.Response(headers, code=206).to_bytes()

    def __repr__(self):
        return '<{} path={}, range={}-{}, len(buffer)={}>'.format(
            self.__class__.__name__,
            self.path,
            self.start, self.end,
            len(self.buffer))

    def need_read(self):
        return False

    def need_write(self):
        return self.buffer or self.end is None or self.file.tell() < self.end

    def do_write(self):
        if not self.buffer:
            bufsize = 0x20000 # 128Ki
            if self.end is not None:
                bufsize = min(bufsize, self.end - self.file.tell())
            self.buffer = self.file.read(bufsize)
            if not self.buffer:
                self.on_done()
        if self.buffer:
            self.buffer = self.buffer[self.socket.send(self.buffer):]
        if not self.need_write():
            self.on_done()


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
        from . import http
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
        self.out_buf += http.Response([
            ('CONTENT-LENGTH', str(len(response_body))),
            ('CONTENT-TYPE', 'text/xml; charset="utf-8"'),
            ('DATE', http.rfc1123_date()),
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
