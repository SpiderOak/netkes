import sys

from wsgi_util import http_status


ee = ('<html><head><title>%(status)s</title></head>'
      '<body><h1>%(status)s</h1><p>%(message)s</p></body></html>\r\n')


def SuperSimple(message, status=http_status.OK,
                headers=(), ctype='text/plain', exc_info=()):
    def app(environ, start_response):
        start_response(status,
                       [('Content-type', ctype),
                        ('Content-length', str(len(message)))] + list(headers),
                       exc_info)
        return [message]
    return app


def Simple(message, status=http_status.OK,
           headers=(), ctype='text/html', exc_info=()):
    body = ee % dict(status=status, message=message)
    return SuperSimple(body, status, headers, ctype, exc_info)


def BadRequest(extra_headers=()):
    return Simple('Bad request.', http_status.BAD_REQUEST, list(extra_headers))


def NotImplemented(extra_headers=()):
    return Simple('Not implemented.', http_status.NOT_IMPLEMENTED, list(extra_headers))


def ServerError(extra_headers=()):
    return Simple('An internal server error has occurred. '
                  'Please try again later.',
                  http_status.SERVER_ERROR,
                  list(extra_headers),
                  exc_info=sys.exc_info())


def NotFound(extra_headers=()):
    return Simple('Not found.', http_status.NOT_FOUND, list(extra_headers))


def Created(extra_headers=()):
    return Simple('Created.', http_status.CREATED, list(extra_headers))


def NotModified(extra_headers=()):
    def app(environ, start_response):
        start_response(http_status.NOT_MODIFIED, list(extra_headers))
        return []
    return app


def MovedPermanently(location, extra_headers=()):
    return Simple('The requested resource has moved to '
                  '<a href="%(location)s">%(location)s</a>.' % locals(),
                  http_status.MOVED_PERMANENTLY,
                  [('Location', location)] + list(extra_headers))


def SeeOther(location, extra_headers=()):
    return Simple('The requested resource was found at '
                  '<a href="%(location)s">%(location)s</a>.' % locals(),
                  http_status.SEE_OTHER,
                  [('Location', location)] + list(extra_headers))


def RangeNotSatisfiable(size, extra_headers=()):
   return Simple('Requested range not satisfiable.',
                 http_status.RANGE_NOT_SATISFIABLE,
                 [('Content-range', '*/%d' % (size,))] + list(extra_headers))


def HelloWorld(extra_headers=()):
    return Simple('Hello World!', ctype='text/plain', headers=list(extra_headers))


def Options(methods, extra_headers=()):
    methods = ', '.join(methods)
    return Simple('The requested resource supports the following methods: ' +
                  methods, headers=[('Allow', methods)] + list(extra_headers))


def MethodNotAllowed(methods, extra_headers=()):
    return Simple('Method not allowed.',
                  http_status.METHOD_NOT_ALLOWED,
                  [('Allow', ', '.join(methods))] + list(extra_headers))


def Forbidden(extra_headers=()):
    return Simple('Forbidden.',
                  http_status.FORBIDDEN,
                  list(extra_headers))


def Unauthorized(challenge, extra_headers=()):
    return Simple('Unauthorized.',
                  http_status.UNAUTHORIZED,
                  [('WWW-Authenticate', challenge)] + list(extra_headers))

def Teapot(extra_headers=()):
    return Simple("I'm a teapot.",
                  http_status.IM_A_TEAPOT,
                  list(extra_headers))
