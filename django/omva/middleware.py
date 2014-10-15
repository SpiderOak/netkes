class ForceHTTPSMiddleware(object):
    def process_request(self, request):
        request.META['HTTP_X_FORWARDED_PROTO'] = 'https'
