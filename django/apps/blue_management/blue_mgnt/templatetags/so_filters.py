from django import template
from django.utils import formats

register = template.Library()

@register.filter(is_safe=True)
def sofilesizeformat(bytes):
    """
    Like the django filesizeformat except with decimal file sizes.
    """
    try:
        bytes = float(bytes)
    except (TypeError, ValueError, UnicodeDecodeError):
        value = "%(size)d byte", "%(size)d bytes" % {'size': 0}
        return avoid_wrapping(value)

    filesize_number_format = lambda value: formats.number_format(round(value, 1), 1)

    KB = 10 ** 3
    MB = 10 ** 6
    GB = 10 ** 9
    TB = 10 ** 12
    PB = 10 ** 15

    if bytes < KB:
        value = "%s bytes" % bytes
    elif bytes < MB:
        value = "%s KB" % filesize_number_format(bytes / KB)
    elif bytes < GB:
        value = "%s MB" % filesize_number_format(bytes / MB)
    elif bytes < TB:
        value = "%s GB" % filesize_number_format(bytes / GB)
    elif bytes < PB:
        value = "%s TB" % filesize_number_format(bytes / TB)
    else:
        value = "%s PB" % filesize_number_format(bytes / PB)

    return value
