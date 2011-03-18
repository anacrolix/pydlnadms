
class Resource:

    def __init__(self, context):
        request = context.request
        units, range = request['range'].split('=', 1)
        assert units == 'bytes', units
        start, end = range.split('-', 1)
        self.start = int(start) if start else 0
        self.end = int(end) + 1 if end else None
        del start, end, units, range
        self.path = request.path[len(RESOURCE_PATH):]
        self.file = open(self.path, 'rb')
        size = os.fstat(self.file.fileno()).st_size
        if self.end is None:
            # TODO: do we have to determine the end of the stream?
            self.end = size
            #pass
        else:
            self.end = min(self.end, size)
        self.file.seek(self.start)
        self.socket = context.socket
        headers = [
            ('Server', SERVER_FIELD),
            ('Date', rfc1123_date()),
            ('Ext', ''),
            ('transferMode.dlna.org', 'Streaming'),
            ('Content-Type', mimetypes.guess_type(self.path)[0]),
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
        self.on_done = context.on_done

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
            bufsize = 0x20000 # 128K
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

    def on_done(self):
        if self.need_read() or self.need_write():
            self.socket.close()

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
            ('SERVER', SERVER_FIELD)
        ], response_body)

    def do_write(self):
        self.out_buf = self.out_buf[self.socket.send(self.out_buf):]
        if not self.out_buf:
            self.on_done()

    def soap_Browse(self, **soap_args):
        from xml.sax.saxutils import escape
        result, total_matches = cd_browse_result(
            self.dms.path,
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
