from ..dlna import *
from ..resources import *
from ..http import *

from ..misc import guess_mimetype

class DLNAResponse:

    def __call__(self, context):
        self.response_headers = [
            ('Ext', None),
            ('transferMode.dlna.org', 'Streaming'),]
        # TODO: wtf does this mean?
        #('realTimeInfo.dlna.org', 'DLNA.ORG_TLAG=*')
        self.request = request
        self.resource = self.get_resource()
#~ #~
    def __call__(self, context):
        resource = self.resource
        if resource.length:
            response_headers += [('Content-Length', resource.length)]
        response_headers.append((CONTENTFEATURES_DLNA_ORG, self.content_features))
        context.start_response(206, self.response_headers)
        while True:
            buf = self.resource.read(0x2000)
            context.socket.sendall(buf)

def dlna_npt_to_seconds(npt_time):
    import datetime
    if ':' in npt_time:
        hours, mins, secs = map(float, npt_time.split(':'))
        return datetime.timedelta(hours=hours, minutes=mins, seconds=secs).total_seconds()
    else:
        return float(npt_time)

def transcode_resource(context):
    request = context.request
    if TIMESEEKRANGE_DLNA_ORG in request:
        ranges_field = HTTPRangeField.from_string(request[TIMESEEKRANGE_DLNA_ORG])
    else:
        ranges_field = HTTPRangeField({'npt': HTTPRange()})
    npt_range = ranges_field['npt']
    npt_range.size = '*'
    context.start_response(206, [
        (CONTENTFEATURES_DLNA_ORG, DLNAContentFeatures(
            support_time_seek=True,
            transcoded=True)),
        ('Ext', None),
        ('transferMode.dlna.org', 'Streaming'),
        (TIMESEEKRANGE_DLNA_ORG, HTTPRangeField({'npt': npt_range})),
        ('Content-Type', 'video/mpeg'),])
    start = npt_range.start
    end = npt_range.end
    transcoder_args = [
        './transcode',
        request.query['path'][-1],
        str(dlna_npt_to_seconds(start)) if start else start,
        str(dlna_npt_to_seconds(end)) if end else end]
    import subprocess, os
    subprocess.check_call(
        transcoder_args,
        stdin=open(os.devnull, 'rb'),
        stdout=context.socket,
        close_fds=True)

def thumbnail_resource(context):
    resource = ThumbnailResource(context.request.query['path'][-1])
    context.start_response(200, [('Content-Type', 'image/jpeg')])
    import subprocess, os
    subprocess.check_call([
            'ffmpegthumbnailer',
            '-i', path,
            '-o', '/dev/stdout',
            '-c', 'jpeg',],
        stdin=open(os.devnull, 'rb'),
        stdout=context.socket,
        close_fds=True)

def file_resource(context):
    request = context.request
    path = request.query['path'][-1]
    if 'Range' in request:
        ranges_field = HTTPRangeField.from_string(request['Range'])
    else:
        ranges_field = HTTPRangeField({'bytes': HTTPRange()})
    bytes_range = ranges_field['bytes']
    resource = FileResource(
        path,
        int(bytes_range.start) if bytes_range.start else 0,
        int(bytes_range.end) + 1 if bytes_range.end else None)
    bytes_range.size = resource.size
    response_headers = [
        ('Content-Range', HTTPRangeField({'bytes': bytes_range})),
        ('Accept-Ranges', 'bytes'),
        ('Content-Type', guess_mimetype(path)),
        (CONTENTFEATURES_DLNA_ORG, DLNAContentFeatures(support_range=True)),
        ('Ext', None),
        ('transferMode.dlna.org', 'Streaming'),]
    if resource.length:
        response_headers.append(('Content-Length', resource.length))
    context.start_response(206, response_headers)
    import socket, errno
    while True:
        data = resource.read(0x10000)
        if not data:
            break
        try:
            context.socket.sendall(data)
        except socket.error as exc:
            if exc.errno == errno.EPIPE:
                break


