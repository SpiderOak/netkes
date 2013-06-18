import Cookie
from urllib import unquote


def read_cookie(app):
    def read_cookie(environ, start_response):
        try:
            cookie = Cookie.SimpleCookie(environ.get('HTTP_COOKIE', ''))
        except Cookie.CookieError:
            pass
        else:
            environ['cookie_data'] = dict((k, v.value and unquote(v.value)) for k, v in cookie.items())
        return app(environ, start_response)
    return read_cookie
