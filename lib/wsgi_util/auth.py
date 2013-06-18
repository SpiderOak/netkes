import base64


def parse_auth_header(header):
    scheme, data = header.split(' ', 1)
    if scheme != 'Basic':
        raise ValueError('%s authentication scheme not supported.' % (scheme,))
    return base64.b64decode(data).split(':', 1)
