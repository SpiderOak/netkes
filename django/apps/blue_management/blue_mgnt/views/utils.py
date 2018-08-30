
OFFENDING_CSV_CHARS = set('@+-=|%')


def is_injection(s):
    return len(s) > 0 and s[0] in OFFENDING_CSV_CHARS


def escape(payload):
    '''
    Escapes CSV payloads to prevent Excel injection.
    Works only on str, and bypasses any other type.
    '''
    if isinstance(payload, str) and is_injection(payload):
        payload = payload.replace("|", "\|")
        payload = "'" + payload + "'"
    return payload


def escape_row(row):
    '''
    Escapes a row of elements to be passed to a csv writer
    '''
    return map(escape, row)
