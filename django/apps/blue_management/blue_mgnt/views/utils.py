def escape(payload):
    '''
    Escapes CSV payloads to prevent Excel injection
    '''
    if payload[0] in ('@', '+', '-', '=', '|', '%'):
        payload = payload.replace("|", "\|")
        payload = "'" + payload + "'"
    return payload


def sanitize_csv_row(row):
    '''
    Escapes a row of elements to be passed to a csv writer
    '''
    for element in row:
        if isinstance(element, str):
            yield escape(element)
        else:
            yield element
