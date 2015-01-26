import json
import urllib.request, urllib.error, urllib.parse
from base64 import b64encode
from urllib.parse import urlencode
from urllib.parse import urljoin

from netkes.Pandora.https import VerifiedHTTPSHandler


_DEFAULT_HANDLERS = [
    urllib.request.ProxyHandler,
    urllib.request.HTTPDefaultErrorHandler,
    urllib.request.HTTPRedirectHandler,
    urllib.request.HTTPErrorProcessor,
    urllib.request.HTTPHandler,
]
def _make_opener(url):
    opener = urllib.request.OpenerDirector()
    for handler_class in _DEFAULT_HANDLERS:
        opener.add_handler(handler_class())
    opener.add_handler(VerifiedHTTPSHandler())
    return opener


class RequestWithMethod(urllib.request.Request):
    _method = None

    def set_method(self, method):
        self._method = method

    def get_method(self):
        return self._method or urllib.request.Request.get_method(self)


class ApiClient(object):
    def __init__(self, base, username, password):
        self.base = base
        self.username = username
        self.password = password
        self.opener = _make_opener(base)

    def open(self, path, data=None, headers=None, method=None):
        if headers is None:
            headers = {}
        if (
            self.username and
            'authorization' not in set(k.lower() for k in headers)
        ):
            headers['authorization'] = 'Basic {}'.format(
                b64encode(('%s:%s' % (
                    self.username, self.password
                )).encode()).strip().decode()
            )
        base = self.base
        encoded_data = None
        if data:
            encoded_data = data.encode()
        req = RequestWithMethod(urljoin(self.base, path), encoded_data, headers)
        req.set_method(method)
        return self.opener.open(req)

    def get(self, path):
        return self.open(path)

    def get_json(self, path):
        return json.loads(self.get(path).read().decode())

    def post(self, path, data, headers=None):
        if not isinstance(data, str):
            data = urlencode(data)
        return self.open(path, data, headers)

    def post_json_raw_response(self, path, data, headers=None):
        return self.post(path, json.dumps(data), headers)

    def post_json(self, path, data, headers=None):
        body = self.post_json_raw_response(path, data, headers).read()
        if body:
            return json.loads(body.decode())
        return None

    def delete(self, path, headers=None):
        return self.open(path, headers=headers, method='DELETE')
