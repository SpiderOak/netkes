def messages():
    status = dict(
        CONTINUE                = (100, "Continue"),
        SWITCHING_PROTOCOLS     = (101, "Switching Protocols"),
        
        OK                      = (200, "OK"),
        CREATED                 = (201, "Created"),
        ACCEPTED                = (202, "Accepted"),
        NON_AUTHORITATIVE       = (203, "Non-Authoritative Information"),
        NO_CONTENT              = (204, "No Content"),
        RESET_CONTENT           = (205, "Reset Content"),
        PARTIAL_CONTENT         = (206, "Partial Content"),
        
        MULTIPLE_CHOICES        = (300, "Multiple Choices"),
        MOVED_PERMANENTLY       = (301, "Moved Permanently"),
        FOUND                   = (302, "Found"),
        SEE_OTHER               = (303, "See Other"),
        NOT_MODIFIED            = (304, "Not Modified"),
        USE_PROXY               = (305, "Use Proxy"),
        TEMP_REDIRECT           = (307, "Temporary Redirect"),
        
        BAD_REQUEST             = (400, "Bad Request"),
        UNAUTHORIZED            = (401, "Unauthorized"),
        PAYMENT_REQUIRED        = (402, "Payment Required"),
        FORBIDDEN               = (403, "Forbidden"),
        NOT_FOUND               = (404, "Not Found"),
        METHOD_NOT_ALLOWED      = (405, "Method Not Allowed"),
        NOT_ACCEPTABLE          = (406, "Not Acceptable"),
        PROXY_AUTH_REQUIRED     = (407, "Proxy Authentication Required"),
        REQUEST_TIME_OUT        = (408, "Request Time-out"),
        CONFLICT                = (409, "Conflict"),
        GONE                    = (410, "Gone"),
        LENGTH_REQUIRED         = (411, "Length Required"),
        PRECONDITION_FAILED     = (412, "Precondition Failed"),
        ENTITY_TOO_LARGE        = (413, "Request Entity Too Large"),
        URI_TOO_LARGE           = (414, "Request-URI Too Large"),
        UNSUPPORTED_MEDIA_TYPE  = (415, "Unsupported Media Type"),
        RANGE_NOT_SATISFIABLE   = (416, "Requested Range Not Satisfiable"),
        EXPECTATION_FAILED      = (417, "Expectation Failed"),
        IM_A_TEAPOT             = (418, "I am a teapot"),
        
        SERVER_ERROR            = (500, "Internal Server Error"),
        NOT_IMPLEMENTED         = (501, "Not Implemented"),
        BAD_GATEWAY             = (502, "Bad Gateway"),
        SERVICE_UNAVAILABLE     = (503, "Service Unavailable"),
        GATEWAY_TIME_OUT        = (504, "Gateway Time-out"),
        VERSION_NOT_SUPPORTED   = (505, "HTTP Version Not Supported"),
    )
    
    messages = dict(status.itervalues())
    status = dict((k, '%d %s' % v) for k, v in status.iteritems())
    status['messages'] = messages
    return status

messages = messages()
__all__ = list(messages.keys())
locals().update(messages)
