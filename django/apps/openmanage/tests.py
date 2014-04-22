import unittest
from mock import Mock, MagicMock, sentinel, patch
import urllib 

from django.test.client import Client
from openmanage import views

from netkes import common
from Pandora.serial import dumps, loads, register_all
from key_escrow import server

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

def random_string(size):
    "return cryptographically secure string of specified size"
    return os.urandom(size)

def new_session_key(size):
    """
    make session key suitable for use for encrypting data via rsa
    """
    # XXX: there's a bug in Crypto.PublicKey.RSA.
    # It loses the first byte if it is NUL, so until this is fixed, we
    # don't use keys with a first byte of \x00 
    key = random_string(size)
    while key[0]  == "\x00":
        key = random_string(size)

    return key

def make_escrow_layer(pub_key_id, pub_key, data, sign_key):
    """
    make an escrow layer (string) that includes the binary data

    pub_key_id = string to identify the private key the layer can be read with
    pub_key = public key object for the escrow party at this layer
    data = binary data to store
    sign_key = private key object of the user signing the layer

    returns binary string
    """

    aes_key = new_session_key(AES_KEY_SIZE)
    aes_iv = sha256(str(time.time())).digest()[:AES_NONCE_SIZE]
    aes = AES.new(aes_key, AES.MODE_CFB, aes_iv)
    aes_encoded_data = aes.encrypt(data)

    payload = zlib.compress(json.dumps(dict(
        aes_key = b2a_base64(
            pub_key.encrypt(aes_key, random_string(len(aes_key)))[0]),
        aes_iv = b2a_base64(aes_iv),
        data = b2a_base64(aes_encoded_data))))

    sig_hmac = hmac.new(key='', msg=payload, digestmod=sha256).digest()
    sig = long_to_bytes(sign_key.sign(sig_hmac, random_string(len(sig_hmac)))[0])

    struct_format = "!HHHL%ds%ds%ds%ds" % (
        len(pub_key_id), len(sig_hmac), len(sig), len(payload), )

    return struct.pack(struct_format,
        len(pub_key_id), len(sig_hmac), len(sig), len(payload),
        pub_key_id, sig_hmac, sig, payload)

def escrow_binary(escrow_key_layers, data, sign_key):
    """
    write binary escrowed data, signed by private key, to the given escrow
    layers
    """

    layer_data = data
    for idx, layer in enumerate(escrow_key_layers):
        layer_data = make_escrow_layer(
            layer[0], layer[1], layer_data, sign_key)

    return layer_data

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
        self.username = urllib.quote('test_username')
        self.client = Client()
        
    def test_fails_with_bad_params(self):
        response = self.client.post('/openmanage/authsession/', {})
        self.assertEqual(response.status_code, 400)

        data = {
            'brand_id': self.brand_identifier,
        }
        response = self.client.post('/openmanage/authsession/', data)
        self.assertEqual(response.status_code, 400)

        data = {
            'username': [self.username],
        }
        response = self.client.post('/openmanage/authsession/', data)
        self.assertEqual(response.status_code, 400)

    def test_succeeds_with_good_params(self):
        data = {
            'brand_id': self.brand_identifier,
            'username': [self.username],
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
            'username': username,
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

if __name__ == "__main__":
    unittest.main()












