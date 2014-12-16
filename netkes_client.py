"""A netkes authentication client.

Abstracts communication with a netkes server.
"""
import os
import logging
import json
from base64 import b64decode, b64encode

import requests
import bcrypt

import warnings
with warnings.catch_warnings():
    # ignore: UserWarning: reimporting '_cffi__xe8229e48xefb54d7c' might
    # overwrite older definitions
    warnings.simplefilter('ignore')
    from nacl.secret import SecretBox

from Crypto.PublicKey import RSA

from key_escrow.write import escrow_binary
from Pandora import serial

# bcrypt kdf iterations
ITERATIONS = 100 # from py-bcrypt readme, may need to be tweaked


class NetkesClient(object):
    def __init__(self, url):
        self.log = logging.getLogger(self.__class__.__name__)
        if not url.endswith('/'):
            url += '/'
        self.url = url
        self.brand = None
        self.username = None
        self.password = None
        self.layers = None
        self.challenge_b64 = None
        self.challenge = None

    def get_auth_params(self):
        # TODO: check that we're logged in
        sign_key = RSA.generate(1024, os.urandom)
        json_auth = json.dumps({
            'challenge': self.challenge_b64,
            'password': self.password,
        })
        escrowed_auth = escrow_binary(self.layers, json_auth, sign_key)
        return {
            'brand_id': self.brand,
            'username': self.username,
            'auth': b64encode(escrowed_auth),
            # NOTE: If we don't send sign_key, then netkes won't do any
            # verification. Of course, if we send the sign_key along with they
            # payload to verify, then it's kind of pointless anyway.
            #'sign_key': serial.dumps(sign_key.publickey()),
        }

    def login(self, brand, username, password, verify=True):
        self.log.info('logging in with brand %r, username %r', brand, username)

        self.brand = brand
        self.username = username
        self.password = password

        self.log.debug('requesting challenge')
        r = requests.get(self.url + 'authsession', params={
            'brand_id': self.brand,
            'username': self.username,
        })
        data = r.json()

        self.log.debug('received challenge')
        self.layers = serial.loads(b64decode(data['layer_data']))
        self.challenge_b64 = data['challenge']
        self.challenge = b64decode(self.challenge_b64)
        # TODO: should also get a session token of some kind. probably a cookie
        # http://docs.python-requests.org/en/latest/user/quickstart/#cookies

        if not verify:
            self.log.debug('login verification not requested')
            return

        self.log.debug('verifying login')
        r = requests.get(self.url + 'auth', params=self.get_auth_params())
        assert r.content == 'OK'
        self.log.debug('login verified')

    def read_data(self, escrowed_data, sign_key, layer_count=None):
        self.log.info('reading data from %d escrowed bytes', len(escrowed_data))

        # TODO: check that we're logged in

        post_data = {
            'escrow_data': escrowed_data,
            'sign_key': serial.dumps(sign_key)
        }
        if layer_count is not None:
            post_data['layer_count'] = layer_count

        self.log.debug('requesting read_data')
        r = requests.post(
            self.url + 'data', params=self.get_auth_params(), data=post_data)
        boxed_data = r.content
        self.log.debug('got %d byte response from read_data', len(boxed_data))

        self.log.debug('unboxing response')
        key = bcrypt.kdf(
            self.password.encode('utf-8'),
            self.challenge,
            SecretBox.KEY_SIZE, ITERATIONS
        )
        box = SecretBox(key)
        data = box.decrypt(boxed_data)
        self.log.debug('unboxed response, got %d bytes', len(data))

        return data
