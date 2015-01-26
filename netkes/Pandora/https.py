"""A certificate-validating HTTPS handler for urllib.

http://stackoverflow.com/questions/1087227/validate-ssl-certificates-with-python
"""

import http.client
import re
import socket
import urllib.request, urllib.error, urllib.parse
import ssl
import sys

_KES_CERT = '''
-----BEGIN CERTIFICATE-----
MIIFkDCCA3gCCQCdG/jvT/y4VjANBgkqhkiG9w0BAQUFADCBiTELMAkGA1UEBhMC
VVMxETAPBgNVBAgTCElsbGlub2lzMRAwDgYDVQQHEwdDaGljYWdvMRcwFQYDVQQK
Ew5TcGlkZXJPYWssIEluYzEZMBcGA1UEAxMQTWF0dGhldyBFcmlja3NvbjEhMB8G
CSqGSIb3DQEJARYSbWF0dEBzcGlkZXJvYWsuY29tMB4XDTExMDkxMjE1MTMxOFoX
DTIxMDkxMTE1MTMxOFowgYkxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhJbGxpbm9p
czEQMA4GA1UEBxMHQ2hpY2FnbzEXMBUGA1UEChMOU3BpZGVyT2FrLCBJbmMxGTAX
BgNVBAMTEE1hdHRoZXcgRXJpY2tzb24xITAfBgkqhkiG9w0BCQEWEm1hdHRAc3Bp
ZGVyb2FrLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKqhrhuH
NnCGYvgtnPEF1dhi2JGtwhDi0ep/EuQbhbGjrfLk12QB4NI2yK4Bxf1Aogl2yPiD
3BSgz70rGsBy0nNbHnfRJDaRj8OqxpcsWjyGns9Yw79GeJUB/3Zq/DBHCbJeHOux
nJt4dW1ZyvEYMQjA8SlmbobzMpSvCwAHHkuGIf5RDr6M8ZaaN+pQ1zZm5dBJgq9D
SuK8fpKO4DULTdFeaT225kWFJXx+8jgbhJNvv8PE5pacspwZ4oWO38ThhMz3oCG6
kAa6w8mazmxTeNeG95UUHLUbl+2Gj7cI+JKR8IQKPiDr7ryqvVoiPbvwkOfAssor
VsNNjozaEOgJ+64Cj3ZGTl1cfeFwdQfsqy5JjH2ATKF/VZUjBq8ZYy3Z6GGMffnF
PfCE/I/cpgT/GsKKT7jJYeFGr1QPAb0iy0LG6BtLI2SQ+sndF842JoIKuFZAU72m
8Mlh4Nud3wxhBtw3pP8dDOBOjB+VkvElOE7hdaIUd8RL8+2EQiZZmRRVRzxC+vld
WatjnB0QzCxXaPTHALLQlB2xHA4K5lXbj/mWhwZUY1sLPYOzBbLclZVIBzUZrryI
C5+qI3Ce1OMQHz+l9WTfGmHC+um8IWRi8N7UKu19UMji3qdsz6sYW2t67y1gWkpX
VX1NHdOlpHFvDEvJiT1MmMl7kcw/OmH24fa/AgMBAAEwDQYJKoZIhvcNAQEFBQAD
ggIBAEsnoP4lb7CB+kt4pRM2VBUO4Uhxuc/V3cDbCei8XAMFco24/MwCFlyy3WVL
Mo6V+Sx2s2s02dkfDVhFIORyOIV00Yq6CTDhsmfy6XStY10KcPNo+3MajIznCgMp
TgUNoFMfs5Z5kmNzJtz47DoZs3GP5V3V6tajUfjlAbAmjJv90xnJe856TkzAXq8A
EKI2TzmamgsarNyTCCBVNRtaUFC7w3DN0Oi9AyjVEGzuJPPOGiKvzv5gUnJ3DLoe
G2/E+3IQVbuPO6LyFlNxraQM6UHLEylkXmxemFFiV2vIsHqPxMM9MSL+rnt0335F
s7st7OsFbjRBw77jiPgWY3MA5O5C6Vhcw7N7NtgvuaHWn2GLZnjdpnKzGxSABfqD
rI5kNzUVusy9+XkbC65hEZWF5eUdP2u0+81KSHFRF5wnnCHZuXwNr68QKjZ5tE6X
3cXF4MazbEZq2ywu/u2B0gKeqTZX/6vMWK3lLyiWHftI/3UU3UqTfsx8nET9deB7
vXHy6Uv5njAmG9EY3QF1XJTiFOKtjY63wbfBQf9FTQ4wd/JV8XnTZJ2i8q1A9ZWh
2+aZjKVxajYu3ezq3LVCXXRz0xPh4/6oBGcf2KHHmXiMsC5yBadld4zzaqdAlPi8
v6Yf7goycsxixzuwR/o3UK0z2bGssb4gkYJxEksACgOd+yRM
-----END CERTIFICATE-----
'''


def create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, bind_address=None):
    """Connect to *address* and return the socket object.

    Convenience function.  Connect to *address* (a 2-tuple ``(host,
    port)``) and return the socket object.  Passing the optional
    *timeout* parameter will set the timeout on the socket instance
    before attempting to connect.  If no *timeout* is supplied, the
    global default timeout setting returned by :func:`getdefaulttimeout`
    is used.
    """

    msg = "getaddrinfo returns an empty list"
    host, port = address
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if bind_address is not None:
                sock.bind(bind_address)
            sock.connect(sa)
            return sock

        except socket.error as msg:
            if sock is not None:
                sock.close()

    raise socket.error(msg)


class InvalidCertificateException(http.client.HTTPException, urllib.error.URLError):
    def __init__(self, host, cert, reason):
        http.client.HTTPException.__init__(self)
        self.host = host
        self.cert = cert
        self.reason = reason

    def __str__(self):
        return ('Host %s returned an invalid certificate (%s) %s\n' %
                (self.host, self.reason, self.cert))


class CertValidatingHTTPSConnection(http.client.HTTPConnection):
    default_port = http.client.HTTPS_PORT

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                             ca_certs=None, strict=None, bind_address=None, **kwargs):
        http.client.HTTPConnection.__init__(self, host, port, strict, **kwargs)
        self.key_file = key_file
        self.cert_file = cert_file
        self.ca_certs = ca_certs
        if self.ca_certs:
            self.cert_reqs = ssl.CERT_REQUIRED
        else:
            self.cert_reqs = ssl.CERT_NONE
        self.bind_address = bind_address

    def _GetValidHostsForCert(self, cert):
        if 'subjectAltName' in cert:
            return [x[1] for x in cert['subjectAltName']
                         if x[0].lower() == 'dns']
        else:
            return [x[0][1] for x in cert['subject']
                            if x[0][0].lower() == 'commonname']

    def _ValidateCertificateHostname(self, cert, bincert, hostname):
        hosts = self._GetValidHostsForCert(cert)
        for host in hosts:
            host_re = host.replace('.', '\.').replace('*', '[^.]*')
            if re.search('^%s$' % (host_re,), hostname, re.I):
                return True

        # If we cannot validate against the hostname, try against the
        # KES certificate.
        binary_kes_cert = ssl.PEM_cert_to_DER_cert(_KES_CERT)
        if binary_kes_cert == bincert:
            return True

        return False

    def connect(self):
        sock = create_connection((self.host, self.port), self.timeout, self.bind_address)
        self.sock = ssl.wrap_socket(sock, keyfile=self.key_file,
                                          certfile=self.cert_file,
                                          cert_reqs=self.cert_reqs,
                                          ca_certs=self.ca_certs)
        if self.cert_reqs & ssl.CERT_REQUIRED:
            cert = self.sock.getpeercert()
            bincert = self.sock.getpeercert(binary_form=True)
            hostname = self.host.split(':', 0)[0]
            if not self._ValidateCertificateHostname(cert, bincert, hostname):
                raise InvalidCertificateException(hostname, cert,
                                                  'hostname mismatch')


class VerifiedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, **kwargs):
        urllib.request.AbstractHTTPHandler.__init__(self)
        self._connection_args = kwargs

    def https_open(self, req):
        def http_class_wrapper(host, **kwargs):
            full_kwargs = dict(self._connection_args)
            full_kwargs.update(kwargs)
            return CertValidatingHTTPSConnection(host, **full_kwargs)

        try:
            return self.do_open(http_class_wrapper, req)
        except urllib.error.URLError as e:
            if type(e.reason) == ssl.SSLError and e.reason.args[0] == 1:
                raise InvalidCertificateException(req.host, '',
                                                  e.reason.args[1])
            raise

    https_request = urllib.request.HTTPSHandler.do_request_

