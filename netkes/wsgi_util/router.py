'''A wsgi middleware that dispatches requests.'''

from wsgi_util import http


class router(object):
    def __init__(self, routes=()):
        self.routes = routes

    def __call__(self, environ, start_response):
        if environ['REQUEST_METHOD'] == 'OPTIONS' and environ['PATH_INFO'] == '*':
            return http.HelloWorld()(environ, start_response)
        for rx, methods, application in self.routes:
            m = rx.match(environ['PATH_INFO'])
            if m is None:
                continue
            if methods and environ['REQUEST_METHOD'] not in methods:
                if environ['REQUEST_METHOD'] == 'OPTIONS':
                    return http.Options(methods)(environ, start_response)
                return http.MethodNotAllowed(methods)(environ, start_response)
            environ['SCRIPT_NAME'] += m.group(0)
            environ['PATH_INFO'] = environ['PATH_INFO'][m.end():]
            environ['router.args'] = m.groups()
            environ['router.kwargs'] = m.groupdict()
            return application(environ, start_response)
        else:
            return http.NotFound()(environ, start_response)
