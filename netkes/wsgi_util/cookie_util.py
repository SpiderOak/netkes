import http.cookies
from urllib.parse import unquote


def read_cookie(app):
    def read_cookie(environ, start_response):
        try:
            cookie = http.cookies.SimpleCookie(environ.get('HTTP_COOKIE', ''))
        except http.cookies.CookieError:
            pass
        else:
            environ['cookie_data'] = dict((k, v.value and unquote(v.value)) for k, v in list(cookie.items()))
        return app(environ, start_response)
    return read_cookie
