import json
from urlparse import parse_qs

from wsgi_util import http_status


def dump_json(data, environ, start_response):
    try:
        callback = parse_qs(environ['QUERY_STRING'])['callback'][0]
    except (TypeError, ValueError, IndexError, KeyError):
        data = json.dumps(data)
    else:
        data = '%s(%s)' % (callback, json.dumps(data))
    start_response(http_status.OK, [('Content-type', 'application/javascript'),
                                    ('Content-length', str(len(data)))])
    return [data]


dump_jsonp = dump_json


def read_json(app):
    def read_json(environ, start_response):
        data = ''.join(environ['wsgi.input'])
        try:
            environ['json_data'] = json.loads(data)
        except ValueError:
            pass
        return app(environ, start_response)
    return read_json
