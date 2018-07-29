from core.loggers import log, dlog
from core import messages
from core.vectors import ModuleExec
from core.module import Module
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from tempfile import gettempdir
from SocketServer import ThreadingMixIn
from urlparse import urlparse, urlunparse, ParseResult
from socket import socket
from ssl import wrap_socket
import threading
import re
import os
from OpenSSL.crypto import X509Extension, X509, dump_privatekey, dump_certificate, load_certificate, load_privatekey, PKey, TYPE_RSA, X509Req
from OpenSSL.SSL import FILETYPE_PEM

class CertificateAuthority(object):

    def __init__(self, ca_file='ca.pem', cache_dir=gettempdir()):
        self.ca_file = ca_file
        self.cache_dir = cache_dir
        self._serial = self._get_serial()
        if not os.path.exists(ca_file):
            self._generate_ca()
        else:
            self._read_ca(ca_file)

    def _get_serial(self):
        s = 1
        for c in filter(lambda x: x.startswith('.pymp_'), os.listdir(self.cache_dir)):
            c = load_certificate(FILETYPE_PEM, open(os.path.sep.join([self.cache_dir, c])).read())
            sc = c.get_serial_number()
            if sc > s:
                s = sc
            del c
        return s

    def _generate_ca(self):
        # Generate key
        self.key = PKey()
        self.key.generate_key(TYPE_RSA, 2048)

        # Generate certificate
        self.cert = X509()
        self.cert.set_version(3)
        self.cert.set_serial_number(1)
        self.cert.get_subject().CN = 'ca.mitm.com'
        self.cert.gmtime_adj_notBefore(0)
        self.cert.gmtime_adj_notAfter(315360000)
        self.cert.set_issuer(self.cert.get_subject())
        self.cert.set_pubkey(self.key)
        self.cert.add_extensions([
            X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
            X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
            X509Extension("subjectKeyIdentifier", False, "hash", subject=self.cert),
            ])
        self.cert.sign(self.key, "sha1")

        with open(self.ca_file, 'wb+') as f:
            f.write(dump_privatekey(FILETYPE_PEM, self.key))
            f.write(dump_certificate(FILETYPE_PEM, self.cert))

    def _read_ca(self, file):
        self.cert = load_certificate(FILETYPE_PEM, open(file).read())
        self.key = load_privatekey(FILETYPE_PEM, open(file).read())

    def __getitem__(self, cn):
        cnp = os.path.sep.join([self.cache_dir, '.pymp_%s.pem' % cn])
        if not os.path.exists(cnp):
            # create certificate
            key = PKey()
            key.generate_key(TYPE_RSA, 2048)

            # Generate CSR
            req = X509Req()
            req.get_subject().CN = cn
            req.set_pubkey(key)
            req.sign(key, 'sha1')

            # Sign CSR
            cert = X509()
            cert.set_subject(req.get_subject())
            cert.set_serial_number(self.serial)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(31536000)
            cert.set_issuer(self.cert.get_subject())
            cert.set_pubkey(req.get_pubkey())
            cert.sign(self.key, 'sha1')

            with open(cnp, 'wb+') as f:
                f.write(dump_privatekey(FILETYPE_PEM, key))
                f.write(dump_certificate(FILETYPE_PEM, cert))

        return cnp

    @property
    def serial(self):
        self._serial += 1
        return self._serial


class UnsupportedSchemeException(Exception):
    pass

class ProxyHandler(BaseHTTPRequestHandler):

    r = re.compile(r'http://[^/]+(/?.*)(?i)')

    def __init__(self, request, client_address, server):
        self.is_connect = False
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _connect_to_host(self):
        
        # Get hostname and port to connect to
        if self.is_connect:
            self.hostname, self.port = self.path.split(':')
        else:
            u = urlparse(self.path)
            if u.scheme != 'http':
                raise UnsupportedSchemeException('Unknown scheme %s' % repr(u.scheme))
            self.hostname = u.hostname
            self.port = u.port or 80
            self.path = urlunparse(
                ParseResult(
                    scheme='',
                    netloc='',
                    params=u.params,
                    path=u.path or '/',
                    query=u.query,
                    fragment=u.fragment
                )
            )

        # Connect to destination
        self._proxy_sock = socket()
        self._proxy_sock.settimeout(10)
        self._proxy_sock.connect((self.hostname, int(self.port)))

        # Wrap socket if SSL is required
        if self.is_connect:
            self._proxy_sock = wrap_socket(self._proxy_sock)


    def _transition_to_ssl(self):
        self.request = wrap_socket(self.request, server_side=True, certfile=self.server.ca[self.path.split(':')[0]])

    def do_CONNECT(self):
        self.is_connect = True
        try:
            # Connect to destination first
            self._connect_to_host()

            # If successful, let's do this!
            self.send_response(200, 'Connection established')
            self.end_headers()
            #self.request.sendall('%s 200 Connection established\r\n\r\n' % self.request_version)
            self._transition_to_ssl()
        except Exception, e:
            self.send_error(500, str(e))
            raise
            return

        # Reload!
        self.setup()
        self.ssl_host = 'https://%s' % self.path
        self.handle_one_request()

    def do_request(self):

        # Is this an SSL tunnel?
        if not self.is_connect:
            try:
                # Connect to destination
                self._connect_to_host()
            except Exception, e:
                self.send_error(500, str(e))
                return
            # Extract path

        net_curl_args = [
            '-X',
            self.command,
            '-i'
        ]

        for h in self.headers:
            if h.title().lower() in ('keep-alive', 'proxy-connection', 'connection', 'transfer-encoding'):
                continue
                
            if h.title().lower() == 'host':
                host = self.headers[h]
                
            net_curl_args += [ '-H', '%s: %s' % ( h.title(), self.headers[h] ) ]

        net_curl_args += [ '-H', 'Proxy-Connection: close' ]

        if self.command == 'POST':
            content_len = int(self.headers.getheader('content-length', 0))
            net_curl_args += [ '-d', self.rfile.read(content_len) ]

        if self.ssl_host:
            net_curl_args.append('https://' + host + self.path)
        else:
            net_curl_args.append('http://' + host + self.path)

        result, headers, saved = ModuleExec(
            'net_curl',
            net_curl_args
        ).run()

        dlog.debug('> ' + '\r\n> '.join([ '%s: %s' % (h.title(), self.headers[h]) for h in self.headers ]))
        dlog.debug('< ' + '\r\n< '.join(headers))

        self.wfile.write('\r\n'.join(headers))
        self.wfile.write('\r\n\r\n')
        self.wfile.write(result)

    def __getattr__(self, item):
        if item.startswith('do_'):
            return self.do_request

class MitmProxy(HTTPServer):

    def __init__(self, server_address=('', 8080), RequestHandlerClass=ProxyHandler, bind_and_activate=True, ca_file='ca.pem'):
        HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.ca = CertificateAuthority(ca_file)
        self._res_plugins = []
        self._req_plugins = []

    def register_interceptor(self, interceptor_class):
        if not issubclass(interceptor_class, InterceptorPlugin):
            raise InvalidInterceptorPluginException('Expected type InterceptorPlugin got %s instead' % type(interceptor_class))
        if issubclass(interceptor_class, RequestInterceptorPlugin):
            self._req_plugins.append(interceptor_class)
        if issubclass(interceptor_class, ResponseInterceptorPlugin):
            self._res_plugins.append(interceptor_class)

class AsyncMitmProxy(ThreadingMixIn, MitmProxy):
    pass

class Proxy(Module):

    """Proxify local HTTP traffic passing through the target."""

    def init(self):

        self.register_info(
            {
                'author': [
                    'Emilio Pinna'
                ],
                'license': 'GPLv3'
            }
        )

        self.register_arguments([
            { 'name' : '-lhost', 'default' : '127.0.0.1' },
            { 'name' : '-lport', 'default' : 8080, 'type' : int },
            { 'name' : '-no-background', 'action' : 'store_true', 'default' : False, 'help' : 'Run foreground' }
        ])

    def run(self):

        server =AsyncMitmProxy()

        log.warn(messages.module_net_proxy.proxy_set_address_s_i % ( self.args['lhost'], self.args['lport'] ))

        if self.args['no_background']:
            log.warn(messages.module_net_proxy.proxy_started_foreground)
            server.serve_forever()
        else:
            log.warn(messages.module_net_proxy.proxy_started_background)
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
