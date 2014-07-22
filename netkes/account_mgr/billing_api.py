import json
import logging
import urllib
import urllib2

from api_client import ApiClient


class BillingApi(object):
    class Error(Exception):
        pass
    class BadParams(Error):
        pass
    class NotFound(Error):
        pass
    class BadPlan(Error):
        pass
    class BadGroup(Error):
        pass

    @classmethod
    def create(cls, base, username, password):
        client = ApiClient(base, username, password)
        return cls(client)

    def __init__(self, client):
        self.client = client

    def fetch_coupon(self, coupon_code):
        try:
            resp = self.client.post('coupon', {'coupon': coupon_code})
        except urllib2.HTTPError, err:
            import logging
            log = logging.getLogger('admin_actions')
            log.info(err.read())
            raise
        else:
            data = json.loads(resp.read())
            return data

    def create_subscription(self, coupon, quantity, frequency, stripe_memo, stripe_token):
        try:
            resp = self.client.post('create_subscription', {
                'coupon': coupon,
                'quantity': quantity,
                'frequency': frequency,
                'stripe_memo': stripe_memo,
                'stripe_token': stripe_token,
            })
        except urllib2.HTTPError, err:
            import logging
            log = logging.getLogger('admin_actions')
            log.info(err.read())
            raise
        else:
            data = json.loads(resp.read())
            return data['success']

    def get_plans(self):
        return self.client.get_json('plans')

    def stripe_public_key(self):
        try:
            return self.client.get_json('stripe_public_key')
        except urllib2.HTTPError, err:
            import logging
            log = logging.getLogger('admin_actions')
            log.info(err.read())
            raise
