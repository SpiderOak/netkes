from urlparse import parse_qs


def read_postdata(app):
    def read_postdata(environ, start_response):
        data = ''.join(environ['wsgi.input'])
        environ['post_data'] = parse_qs(data)
        return app(environ, start_response)
    return read_postdata


def read_querydata(app):
    def read_querydata(environ, start_response):
        environ['query_data'] = parse_qs(environ['QUERY_STRING'])
        return app(environ, start_response)
    return read_querydata
