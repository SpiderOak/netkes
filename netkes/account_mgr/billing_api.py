import json
import logging
import requests

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
        self.logger = logging.getLogger('admin_actions')

    def fetch_coupon(self, coupon_code):
        try:
            resp = self.client.post('coupon', {'coupon': coupon_code})
        except requests.exceptions.HTTPError, err:
            self.logger.info(err.response.json())
            raise
        else:
            if resp.text:
                return resp.json()

    def create_subscription(self, coupon, frequency, stripe_token):
        try:
            resp = self.client.post('create_subscription', {
                'coupon': coupon,
                'frequency': frequency,
                'stripe_token': stripe_token,
            })
        except requests.exceptions.HTTPError, err:
            self.logger.info(err.response.json())
            raise
        else:
            if resp.text:
                return resp.json()

    def billing_info(self):
        try:
            return self.client.get_json('billing_info')
        except requests.exceptions.HTTPError, err:
            self.logger.info(err.response.json())
            raise
