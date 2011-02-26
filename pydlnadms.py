#!/usr/bin/env python3

import collections, logging, platform, select, socket, struct, sys, time

def make_xml_service_description(actions, statevars):
    from xml.etree.ElementTree import Element, tostring, SubElement
    scpd = Element('scpd', xmlns='urn:schemas-upnp-org:service-1-0')
    specVersion = SubElement(scpd, 'specVersion')
    SubElement(specVersion, 'major').text = '1'
    SubElement(specVersion, 'minor').text = '0'
    actionList = SubElement(scpd, 'actionList')
    serviceStateTable = SubElement(scpd, 'serviceStateTable')
    return tostring(scpd).encode('utf-8')

SSDP_PORT = 1900
SSDP_MCAST_ADDR = '239.255.255.250'
UPNP_ROOT_DEVICE = 'upnp:rootdevice'
UPNP_DOMAIN_NAME = 'schemas-upnp-org'
ROOT_DESC_PATH = '/rootDesc.xml'
SERVER_FIELD = '{}/{} DLNADOC/1.50 UPnP/1.0 MiniDLNA/1.0'.format(
    *platform.linux_distribution()[0:2])
ROOT_DEVICE = 'urn:schemas-upnp-org:device:MediaServer:1'
DEVICE_DESC_SERVICE_FIELDS = 'serviceType', 'serviceId', 'SCPDURL', 'controlURL', 'eventSubURL'
Service = collections.namedtuple(
    'Service',
    DEVICE_DESC_SERVICE_FIELDS + ('xmlDescription',))

SERVICE_LIST = []
for service, domain, version, actions, statevars in [
        ('ContentDirectory', None, 1, (), ()),
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


class SSDP:
    def __init__(self, host):
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.recv_sock.bind((host, SSDP_PORT))
        mreq = struct.pack('4sI', socket.inet_aton(SSDP_MCAST_ADDR), socket.INADDR_ANY)
        self.recv_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        #for if_addr in if_addrs:
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # don't loop back multicast packets to the local sockets
        self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, False)
        # perhaps the local if should be the host?
        mreq = struct.pack('II', socket.INADDR_ANY, socket.INADDR_ANY)
        self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreq)
        self.send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        self.send_sock.bind((host, 0))


def make_http_response(protocol, code, reason, fields):
    from itertools import chain
    return '\r\n'.join(chain(
        ('{} {} {}'.format(protocol, code, reason),),
        (': '.join(f) for f in fields),
        ('', '')))

def rfc1123_date():
    return time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())

class HTTPConnection:

    def __init__(self, socket, root_device):
        self.socket = socket
        self.buffer = b''
        self.root_device = root_device
        self.conns = root_device.http_conns

    def send_description(self, desc):
        data = make_http_response(
            'HTTP/1.1', 200, 'OK', (
                ('CONTENT-LENGTH', str(len(desc))),
                ('CONTENT-TYPE', 'text/xml'),
                ('DATE', rfc1123_date()),
            )).encode('utf-8') + desc
        sent = self.socket.send(data)
        assert sent == len(data)
        logging.debug('Sent description %s->%s: %r', self.socket.getsockname(), self.socket.getpeername(), data)


    def handle_read(self):
        data = self.socket.recv(0x1000)
        if not data:
            self.conns.remove(self)
            return
        logging.debug('%s to %s: %r', self.socket.getpeername(), self.socket.getsockname(), data)
        self.buffer += data
        header, body = self.buffer.split(b'\r\n\r\n', 1)
        header = header.decode('utf-8')
        fields = header.split('\r\n')
        method, path, protocol = fields[0].split()
        if method in ('GET', 'HEAD'):
            if path == ROOT_DESC_PATH:
                self.send_description(self.root_device.device_desc)
            else:
                for service in SERVICE_LIST:
                    if path == service.SCPDURL:
                        self.send_description(service.xmlDescription)
                        break

    def fileno(self):
        return self.socket.fileno()

class DMS:

    def __init__(self):
        logging.basicConfig(stream=sys.stderr, level=0)
        self.ssdp = SSDP('')
        # there is much more to it than this
        self.device_uuid = 'uuid:00000000-0000-0000-0000-000000000000'
        self.http_port = 8200
        self.notify_interval = 895
        self.device_desc = make_device_desc(self.device_uuid)
        self.send_ssdp_goodbye()
        self.http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.http_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.http_sock.bind(('', 8200))
        self.http_sock.listen(5)
        self.http_conns = []
        while True:
            r = [self.ssdp.recv_sock, self.http_sock] + self.http_conns
            r, w, x = select.select(r, [], [])
            if self.ssdp.recv_sock in r:
                self.process_ssdp_request()
            if self.http_sock in r:
                sock, addr = self.http_sock.accept()
                logging.debug('Accepted connection from %s', addr)
                self.http_conns.append(HTTPConnection(sock, self))
            for http_conn in self.http_conns:
                if http_conn not in r:
                    continue
                http_conn.handle_read()

    @property
    def all_targets(self):
        yield UPNP_ROOT_DEVICE
        yield self.device_uuid
        yield ROOT_DEVICE
        for service in SERVICE_LIST:
            yield service.serviceType

    def send_ssdp_goodbye(self):
        def send_message(nt, usn):
            buf = '\r\n'.join([
                'NOTIFY * HTTP/1.1',
                'HOST:{}:{:d}'.format(SSDP_MCAST_ADDR, SSDP_PORT),
                'NT:' + nt,
                'USN:' + usn,
                'NTS:ssdp:byebye',
                '', '']).encode('utf-8')
            self.ssdp.send_sock.sendto(buf, (SSDP_MCAST_ADDR, SSDP_PORT))
            logging.debug('Sent ssdp:byebye: %r', buf)
        for nt in self.all_targets:
            send_message(nt, self.usn_from_target(nt))

    def send_ssdp_notify(self):
        def send_message(nt, usn):
            buf = '\r\n'.join([
                'NOTIFY * HTTP/1.1',
                'HOST:{}:{:d}'.format(SSDP_MCAST_ADDR, SSDP_PORT),
                'CACHE-CONTROL:max-age={:u}'.format(self.notify_interval * 2 + 10),
                'LOCATION:http://{}:{:d}{}'.format(host, port, ROOT_DESC_PATH),
                'SERVER: ' + SERVER_FIELD,
                'NT:' + nt,
                'USN:' + usn,
                'NTS:ssdp:alive',
                '', '']).encode('utf-8')
            self.ssdpsend.sendto(buf, (SSDP_MCAST_ADDR, SSDP_PORT))
        for nt in (UPNP_ROOT_DEVICE, ROOT_DEVICE,) + SERVICES:
            send_message(nt, self.device_uuid + '::' + nt)
        send_message(self.device_uiid, self.device_uuid)

    def usn_from_target(self, target):
        if target == self.device_uuid:
            return target
        else:
            return self.device_uuid + '::' + target

    def process_ssdp_request(self):
        data, addr = self.ssdp.recv_sock.recvfrom(0x1000)
        logging.debug('Received UDP packet from %s: %r', addr, data)
        fields = data.decode('utf-8').split('\r\n')
        if not fields[0].startswith('M-SEARCH'):
            return
        for field in fields:
            if field.startswith('ST:'):
                st = field[3:].lstrip()
        if st == 'ssdp:all':
            sts = self.all_targets
        else:
            sts = [st]
        for st in sts:
            self.send_ssdp_msearch_reply(addr, st)

    def send_ssdp_msearch_reply(self, addr, st):
        buf = '\r\n'.join([
            'HTTP/1.1 200 OK',
            'CACHE-CONTROL: max-age={:d}'.format(self.notify_interval * 2 + 10),
            'DATE: ' + time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
            'EXT:',
            'ST: ' + st,
            'USN: ' + self.usn_from_target(st),
            'SERVER: ' + SERVER_FIELD,
            'LOCATION: http://{}:{:d}{}'.format(self.ssdp.recv_sock.getsockname()[0], self.http_port, ROOT_DESC_PATH),
            'Content-Length: 0',
            '', '']).encode('utf-8')
        self.ssdp.send_sock.sendto(buf, addr)
        logging.debug('Responded to M-SEARCH from %s: %r', addr, buf)


#/* ProcessSSDPRequest()
 #* process SSDP M-SEARCH requests and responds to them */
#void
#ProcessSSDPRequest(int s, unsigned short port)
#/*ProcessSSDPRequest(int s, struct lan_addr_s * lan_addr, int n_lan_addr,
                   #unsigned short port)*/
#{
	#int n;
	#char bufr[1500];
	#socklen_t len_r;
	#struct sockaddr_in sendername;
	#int i, l;
	#int lan_addr_index = 0;
	#char * st = NULL, * mx = NULL, * man = NULL, * mx_end = NULL;
	#int st_len = 0, mx_len = 0, man_len = 0, mx_val = 0;
	#len_r = sizeof(struct sockaddr_in);

	#n = recvfrom(s, bufr, sizeof(bufr), 0,
	             #(struct sockaddr *)&sendername, &len_r);
	#if(n < 0)
	#{
		#DPRINTF(E_ERROR, L_SSDP, "recvfrom(udp): %s\n", strerror(errno));
		#return;
	#}

	#if(memcmp(bufr, "NOTIFY", 6) == 0)
	#{
		#/* ignore NOTIFY packets. We could log the sender and device type */
		#return;
	#}
	#else if(memcmp(bufr, "M-SEARCH", 8) == 0)
	#{
		#//DEBUG DPRINTF(E_DEBUG, L_SSDP, "Received SSDP request:\n%.*s", n, bufr);
		#for(i=0; i < n; i++)
		#{
			#if( bufr[i] == '*' )
				#break;
		#}
		#if( !strcasestr(bufr+i, "HTTP/1.1") )
		#{
			#return;
		#}
		#while(i < n)
		#{
			#while((i < n - 1) && (bufr[i] != '\r' || bufr[i+1] != '\n'))
				#i++;
			#i += 2;
			#if((i < n - 3) && (strncasecmp(bufr+i, "ST:", 3) == 0))
			#{
				#st = bufr+i+3;
				#st_len = 0;
				#while(*st == ' ' || *st == '\t') st++;
				#while(st[st_len]!='\r' && st[st_len]!='\n') st_len++;
			#}
			#else if(strncasecmp(bufr+i, "MX:", 3) == 0)
			#{
				#mx = bufr+i+3;
				#mx_len = 0;
				#while(*mx == ' ' || *mx == '\t') mx++;
				#while(mx[mx_len]!='\r' && mx[mx_len]!='\n') mx_len++;
        			#mx_val = strtol(mx, &mx_end, 10);
			#}
			#else if(strncasecmp(bufr+i, "MAN:", 4) == 0)
			#{
				#man = bufr+i+4;
				#man_len = 0;
				#while(*man == ' ' || *man == '\t') man++;
				#while(man[man_len]!='\r' && man[man_len]!='\n') man_len++;
			#}
		#}
		#/*DPRINTF(E_INFO, L_SSDP, "SSDP M-SEARCH packet received from %s:%d\n",
	           #inet_ntoa(sendername.sin_addr),
	           #ntohs(sendername.sin_port) );*/
		#if( ntohs(sendername.sin_port) <= 1024 || ntohs(sendername.sin_port) == 1900 )
		#{
			#DPRINTF(E_INFO, L_SSDP, "WARNING: Ignoring invalid SSDP M-SEARCH from %s [bad source port %d]\n",
			   #inet_ntoa(sendername.sin_addr), ntohs(sendername.sin_port));
		#}
		#else if( !man || (strncmp(man, "\"ssdp:discover\"", 15) != 0) )
		#{
			#DPRINTF(E_INFO, L_SSDP, "WARNING: Ignoring invalid SSDP M-SEARCH from %s [bad MAN header %.*s]\n",
			   #inet_ntoa(sendername.sin_addr), man_len, man);
		#}
		#else if( !mx || mx == mx_end || mx_val < 0 ) {
			#DPRINTF(E_INFO, L_SSDP, "WARNING: Ignoring invalid SSDP M-SEARCH from %s [bad MX header %.*s]\n",
			   #inet_ntoa(sendername.sin_addr), mx_len, mx);
		#}
		#else if( st && (st_len > 0) )
		#{
			#DPRINTF(E_INFO, L_SSDP, "SSDP M-SEARCH from %s:%d ST: %.*s, MX: %.*s, MAN: %.*s\n",
	        	   #inet_ntoa(sendername.sin_addr),
	           	   #ntohs(sendername.sin_port),
			   #st_len, st, mx_len, mx, man_len, man);
			#/* find in which sub network the client is */
			#for(i = 0; i<n_lan_addr; i++)
			#{
				#if( (sendername.sin_addr.s_addr & lan_addr[i].mask.s_addr)
				   #== (lan_addr[i].addr.s_addr & lan_addr[i].mask.s_addr))
				#{
					#lan_addr_index = i;
					#break;
				#}
			#}
			#/* Responds to request with a device as ST header */
			#for(i = 0; known_service_types[i]; i++)
			#{
				#l = strlen(known_service_types[i]);
				#if(l<=st_len && (0 == memcmp(st, known_service_types[i], l)))
				#{
					#/* Check version number - must always be 1 currently. */
					#if( (st[st_len-2] == ':') && (atoi(st+st_len-1) != 1) )
						#break;
					#usleep(random()>>20);
					#SendSSDPAnnounce2(s, sendername,
					                  #i,
					                  #lan_addr[lan_addr_index].str, port);
					#break;
				#}
			#}
			#/* Responds to request with ST: ssdp:all */
			#/* strlen("ssdp:all") == 8 */
			#if(st_len==8 && (0 == memcmp(st, "ssdp:all", 8)))
			#{
				#for(i=0; known_service_types[i]; i++)
				#{
					#l = (int)strlen(known_service_types[i]);
					#SendSSDPAnnounce2(s, sendername,
					                  #i,
					                  #lan_addr[lan_addr_index].str, port);
				#}
			#}
		#}
		#else
		#{
			#DPRINTF(E_INFO, L_SSDP, "Invalid SSDP M-SEARCH from %s:%d\n",
	        	   #inet_ntoa(sendername.sin_addr), ntohs(sendername.sin_port));
		#}
	#}
	#else
	#{
		#DPRINTF(E_WARN, L_SSDP, "Unknown udp packet received from %s:%d\n",
		       #inet_ntoa(sendername.sin_addr), ntohs(sendername.sin_port));
	#}
#}






def main():
    DMS()

if __name__ == '__main__':
    main()
