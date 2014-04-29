import unittest
from mock import Mock, MagicMock, sentinel, patch
import urllib 

from django.test.client import Client
from openmanage import models, views

from netkes import common
from Pandora.serial import dumps, loads, register_all
from key_escrow import server
from key_escrow.write import escrow_binary, random_string

import os
import time
import json
import zlib
import struct
import hmac
from binascii import b2a_base64, a2b_base64
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

AES_KEY_SIZE = 32
AES_NONCE_SIZE = 16

#register_all()
server.load_escrow_key_cache()
_ESCROW_KEYS_CACHE = server._ESCROW_KEYS_CACHE


def encrypt_with_layers(escrow_data, sign_key, brand_identifier):
    escrow_key_layers = loads(server.get_escrow_layers(brand_identifier))

    return escrow_binary(escrow_key_layers, escrow_data, sign_key)

class TestDecrypt(unittest.TestCase):
    def test_encrypt_and_decrypt_with_layers(self):
        config = common.read_config_file()
        brand_identifier = config['api_user']
        escrow_data = "test data"
        sign_key = RSA.generate(2048, random_string)
        escrowed_data = encrypt_with_layers(escrow_data, sign_key, brand_identifier)

        layer_count = 2
        plaintext_data = server.read_escrow_data(brand_identifier, 
                                                 escrowed_data,
                                                 layer_count=layer_count,
                                                 sign_key=sign_key)

        self.assertEqual(escrow_data, plaintext_data) 

class TestStartAuthSession(unittest.TestCase):
    def setUp(self):
        self.config = common.read_config_file()
        self.brand_identifier = self.config['api_user']
        self.client = Client()
        
    def test_fails_with_bad_params(self):
        response = self.client.post('/openmanage/authsession/', {})
        self.assertEqual(response.status_code, 400)

    def test_succeeds_with_good_params(self):
        data = {
            'brand_id': self.brand_identifier,
        }
        response = self.client.post('/openmanage/authsession/', data)
        self.assertEqual(response.status_code, 200)
        


class TestOpenmanage(unittest.TestCase):
    def setUp(self):
        self.client = Client()
        self.sign_key = RSA.generate(2048, random_string)
        self.config = common.read_config_file()
        self.brand_identifier = self.config['api_user']
        self.auth = {
            'password': 'password',
            'challenge': 'challenge',
            
        }
        auth = encrypt_with_layers(json.dumps(self.auth), self.sign_key, 
                                   self.brand_identifier)
        username = urllib.quote('test_username')
        self.post_data = {
            'brand_id': self.brand_identifier,
            'username': username,
            'auth': b2a_base64(auth),
            'escrow_data': sentinel.escrow_data,
            'sign_key': dumps(self.sign_key),
            'layer_count': 2,
        }
        self.session_post_data = {
            'brand_id': self.brand_identifier,
        }

    def test_authentication_required(self):
        del self.post_data['auth']
        response = self.client.post('/openmanage/auth/', self.post_data)
        self.assertEqual(response.status_code, 400)

    @patch('openmanage.views.valid_challenge')
    @patch('openmanage.views.authenticator')
    def test_authentication_fails_on_bad_password(self, authenticator, valid_challenge):
        valid_challenge.return_value = True
        authenticator.return_value = False
        response = self.client.post('/openmanage/auth/', self.post_data)
        self.assertEqual(response.status_code, 403)
        
    @patch('openmanage.views.get_challenge', return_value=['test', time.time()])
    @patch('openmanage.views.valid_challenge')
    @patch('openmanage.views.authenticator')
    def test_authentication_succeeds_on_good_password(self, authenticator, 
                                                      valid_challenge, get_challenge):
        valid_challenge.return_value = True
        authenticator.return_value = True

        response = self.client.post('/openmanage/auth/', self.post_data)
        self.assertEqual(response.status_code, 200)

    @patch('openmanage.views.authenticator')
    def test_authentication_fails_with_invalid_challenge(self, authenticator, ):
        authenticator.return_value = True
        response = self.client.post('/openmanage/auth/', self.post_data)
        self.assertEqual(response.status_code, 403)

    @patch('openmanage.views.authenticator')
    def test_authentication_fails_with_invalid_sign_key(self, authenticator, ):
        authenticator.return_value = True
        self.post_data['sign_key'] = 'bad'
        response = self.client.post('/openmanage/auth/', self.post_data)
        self.assertEqual(response.status_code, 400)

    @patch('openmanage.views.authenticator')
    def test_authentication_fails_when_challenge_expires(self, authenticator, ):
        response = self.client.post('/openmanage/authsession/', self.session_post_data)
        data = json.loads(response.content)
        authenticator.return_value = True
        self.auth['challenge'] = data['challenge']
        auth = encrypt_with_layers(json.dumps(self.auth), self.sign_key, 
                                   self.brand_identifier)

        self.post_data['auth'] = b2a_base64(auth)
        views.CHALLENGE_EXPIRATION_TIME = .00001
        time.sleep(.001)
        response = self.client.post('/openmanage/auth/', self.post_data)
        views.CHALLENGE_EXPIRATION_TIME = 60
        self.assertEqual(response.status_code, 403)

    @patch('openmanage.views.authenticator')
    def test_authentication_fails_when_missing_auth_key(self, authenticator, ):
        response = self.client.post('/openmanage/authsession/', self.session_post_data)
        data = json.loads(response.content)
        authenticator.return_value = True
        del self.auth['challenge']
        auth = encrypt_with_layers(json.dumps(self.auth), self.sign_key, 
                                   self.brand_identifier)

        self.post_data['auth'] = b2a_base64(auth)
        response = self.client.post('/openmanage/auth/', self.post_data)
        self.assertEqual(response.status_code, 400)

    @patch('openmanage.views.authenticator')
    def test_authentication_succeeds_with_valid_challenge(self, authenticator, ):
        response = self.client.post('/openmanage/authsession/', self.session_post_data)
        data = json.loads(response.content)
        authenticator.return_value = True
        self.auth['challenge'] = data['challenge']
        auth = encrypt_with_layers(json.dumps(self.auth), self.sign_key, 
                                   self.brand_identifier)
        self.post_data['auth'] = b2a_base64(auth)
        response = self.client.post('/openmanage/auth/', self.post_data)
        self.assertEqual(response.status_code, 200)

    @patch('openmanage.views.authenticator')
    def test_read_data_successfully_decrypts_escrow_data(self, authenticator, ):
        response = self.client.post('/openmanage/authsession/', self.session_post_data)
        data = json.loads(response.content)
        authenticator.return_value = True
        self.auth['challenge'] = data['challenge']
        auth = encrypt_with_layers(json.dumps(self.auth), self.sign_key, 
                                   self.brand_identifier)
        self.post_data['auth'] = b2a_base64(auth)

        escrow_data = "test data"
        escrowed_data = encrypt_with_layers(escrow_data, self.sign_key, 
                                            self.brand_identifier)
        self.post_data['escrow_data'] = b2a_base64(escrowed_data)

        response = self.client.post('/openmanage/data/', self.post_data)

        username = self.post_data['username']
        secret_box, nonce = views.create_secret_box(self.auth['password'], 
                                                          self.auth['challenge'])
        plaintext = secret_box.decrypt(response.content)

        self.assertEqual(escrow_data, plaintext)

    @patch('openmanage.views.authenticator')
    def test_authentication_not_required_during_auth_window(self, authenticator, ):
        response = self.client.post('/openmanage/authsession/', self.session_post_data)
        data = json.loads(response.content)
        authenticator.return_value = True
        self.auth['challenge'] = data['challenge']
        auth = encrypt_with_layers(json.dumps(self.auth), self.sign_key, 
                                   self.brand_identifier)
        self.post_data['auth'] = b2a_base64(auth)
        response = self.client.post('/openmanage/auth/', self.post_data)
        self.assertEqual(response.status_code, 200)

        response = self.client.post('/openmanage/auth/')
        self.assertEqual(response.status_code, 200)

    @patch('openmanage.views.authenticator')
    def test_authentication_fails_with_expired_auth(self, authenticator, ):
        response = self.client.post('/openmanage/authsession/', self.session_post_data)
        data = json.loads(response.content)
        authenticator.return_value = True
        self.auth['challenge'] = data['challenge']
        auth = encrypt_with_layers(json.dumps(self.auth), self.sign_key, 
                                   self.brand_identifier)
        self.post_data['auth'] = b2a_base64(auth)
        response = self.client.post('/openmanage/auth/', self.post_data)
        self.assertEqual(response.status_code, 200)

        views.CHALLENGE_EXPIRATION_TIME = .00001
        time.sleep(.001)

        response = self.client.post('/openmanage/auth/')
        self.assertEqual(response.status_code, 400)
        views.CHALLENGE_EXPIRATION_TIME = 60


class TestPassword(unittest.TestCase):
    def setUp(self):
        self.client = Client()
        self.log = MagicMock()
        views.logging = MagicMock()
        views.logging.getLogger.return_value = self.log

    def test_set_password_fails_with_missing_arguments(self, ):
        response = self.client.post('/openmanage/password/', {})
        self.log.error.assert_called_with("Got bad request. Missing arguments.")
        self.assertEqual(response.status_code, 200)

    def test_set_password_fails_when_user_does_not_exist(self, ):
        data = dict(email='dne', password='new')
        response = self.client.post('/openmanage/password/', data)
        self.log.error.assert_called_with("Password not found for user")
        self.assertEqual(response.status_code, 200)

    def test_set_password_fails_when_password_set(self, ):
        models.Password.objects.create(email='set', pw_hash='t')
        data = dict(email='set', password='new')
        response = self.client.post('/openmanage/password/', data)
        self.log.error.assert_called_with("Cannot set password. Password already set.")
        self.assertEqual(response.status_code, 200)

    def test_set_password_succeeds(self, ):
        models.Password.objects.create(email='unset', pw_hash='')
        data = dict(email='unset', password='new')
        response = self.client.post('/openmanage/password/', data)
        self.assertEqual(response.status_code, 200)
        p = models.Password.objects.get(email='unset')
        self.assertEqual(p.pw_hash, 'new')

if __name__ == "__main__":
    unittest.main()












