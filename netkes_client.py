"""A netkes authentication client.

Abstracts communication with a netkes server.
"""
import os
import logging
import json
from base64 import b64decode, b64encode
from hashlib import md5

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

    class Error(Exception):
        pass

    class NotLoggedInError(Error):
        pass

    class IncorrectCredentialsError(Error):
        pass

    def __init__(self, url):
        self.log = logging.getLogger(self.__class__.__name__)
        if not url.endswith('/'):
            url += '/'
        self.url = url
        self.session = None
        self.brand = None
        self.username = None
        self.layers = None
        self.challenge_b64 = None
        self.challenge = None
        self.password = None
        self.session_key = None

    def logged_in(self):
        return self.session_key is not None

    def _layer_fingerprint(self, layers):
        h = md5()
        for key_id, key in layers:
            s = '{0}{1}'.format(key_id, key.publickey().exportKey('DER'))
            h.update(s)
        h = h.hexdigest().upper()
        return '-'.join(h[i:i+4] for i in range(0, len(h), 4))

    def start_login(self, brand, username):
        self.log.info('logging in with brand %r, username %r', brand, username)

        self.session = requests.Session()
        self.brand = brand
        self.username = username

        self.log.debug('requesting challenge')
        r = self.session.post(self.url + 'authsession/', data={
            'brand_id': self.brand,
            'username': self.username,
        })
        data = r.json()

        self.log.debug('received challenge')
        self.layers = serial.loads(b64decode(data['layer_data']))
        self.challenge_b64 = data['challenge']
        self.challenge = b64decode(self.challenge_b64)

        return self._layer_fingerprint(self.layers)

    def _get_auth_data(self):
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
            'sign_key': serial.dumps(sign_key.publickey()),
            'layer_count': len(self.layers),
        }

    def finish_login(self, password):
        self.log.debug('finishing login')

        self.password = password

        auth_data = self._get_auth_data()
        r = self.session.post(self.url + 'auth/', data=auth_data)

        if r.status_code == requests.codes.forbidden:
            self.log.warn('incorrect credentials')
            raise self.IncorrectCredentialsError()

        assert r.content == 'OK'

        self.log.debug('login verified, generating session key')
        self.session_key = bcrypt.kdf(
            self.password.encode('utf-8'),
            self.challenge,
            SecretBox.KEY_SIZE, ITERATIONS
        )
        self.log.debug('logged in')

    def read_data(self, escrowed_data, sign_key, layer_count=2):
        self.log.info('reading data from %d escrowed bytes', len(escrowed_data))
        if not self.logged_in():
            self.log.error('read_data attempted while not logged in')
            raise self.NotLoggedInError()

        post_data = {
            'escrow_data': escrowed_data,
            'sign_key': serial.dumps(sign_key),
            'layer_count': layer_count,
        }

        self.log.debug('requesting read_data')
        r = self.session.post(self.url + 'data/', data=post_data)
        boxed_data = r.content
        self.log.debug('got %d byte response from read_data, unboxing',
                       len(boxed_data))

        box = SecretBox(self.session_key)
        data = box.decrypt(boxed_data)
        self.log.debug('unboxed response, got %d bytes', len(data))

        return data
