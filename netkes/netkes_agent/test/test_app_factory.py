import unittest
from mock import Mock, MagicMock, sentinel, patch

patch('wsgi_util.post_util.read_querydata', lambda x: x).start()
patch('wsgi_util.post_util.read_postdata', lambda x: x).start()
from netkes.netkes_agent import app_factory
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

        from Crypto import Random
        for key in _ESCROW_KEYS_CACHE.values():
            key._randfunc = Random.new().read

        layer_count = 2
        plaintext_data = server.read_escrow_data(brand_identifier, 
                                                 escrowed_data,
                                                 layer_count=layer_count,
                                                 sign_key=sign_key)

        self.assertEqual(escrow_data, plaintext_data) 

class TestReadData(unittest.TestCase):
    def setUp(self):
        self.environ = {
            'query_data': {
                'brand_id': [sentinel.brand_id],
            },
            'post_data': {
                'escrow_data': [sentinel.escrow_data],
                'sign_key': [sentinel.sign_key]
            }
        }

    @patch('netkes.netkes_agent.app_factory.BadRequest')
    def test_authentication_required(self, BadRequest):
        app_factory.read_data(self.environ, MagicMock())
        self.assertTrue(BadRequest.called)

    @patch('netkes.netkes_agent.app_factory.server.read_escrow_data')
    @patch('netkes.netkes_agent.app_factory.serial.loads')
    @patch('netkes.netkes_agent.app_factory.unquote')
    @patch('netkes.netkes_agent.app_factory.authenticator')
    @patch('netkes.netkes_agent.app_factory.Forbidden')
    def test_authentication_fails_on_bad_password(self, Forbidden, authenticator, 
                                                  unquote, loads, read_escrow_data):
        self.environ['query_data']['username'] = [sentinel.username]
        self.environ['query_data']['password'] = [sentinel.invalid_password]
        self.environ['query_data']['crypt_pw'] = ['False']
        authenticator.return_value = False
        app_factory.read_data(self.environ, MagicMock())
        self.assertTrue(Forbidden.called)
        
    @patch('netkes.netkes_agent.app_factory.server.read_escrow_data')
    @patch('netkes.netkes_agent.app_factory.serial.loads')
    @patch('netkes.netkes_agent.app_factory.unquote')
    @patch('netkes.netkes_agent.app_factory.authenticator')
    @patch('netkes.netkes_agent.app_factory.SuperSimple')
    def test_authentication_succeeds_on_good_password(self, SuperSimple, authenticator, 
                                                      unquote, loads, read_escrow_data):
        self.environ['query_data']['username'] = [sentinel.username]
        self.environ['query_data']['password'] = [sentinel.valid_password]
        self.environ['query_data']['crypt_pw'] = ['False']
        authenticator.return_value = True
        app_factory.read_data(self.environ, MagicMock())
        self.assertTrue(SuperSimple.called)

    @patch('netkes.netkes_agent.app_factory.unquote')
    @patch('netkes.netkes_agent.app_factory.authenticator')
    @patch('netkes.netkes_agent.app_factory.SuperSimple')
    def test_read_data_successfully_decrypts_escrow_data(self, SuperSimple, 
                                                         authenticator, unquote):
        config = common.read_config_file()
        brand_identifier = config['api_user']
        escrow_data = "test data"
        sign_key = RSA.generate(2048, random_string)
        escrowed_data = encrypt_with_layers(escrow_data, sign_key, brand_identifier)
        self.environ['post_data']['sign_key'] = [dumps(sign_key)]
        self.environ['post_data']['escrow_data'] = [escrowed_data]
        self.environ['post_data']['layer_count'] = [2]
        self.environ['query_data']['username'] = [sentinel.username]
        self.environ['query_data']['password'] = [sentinel.valid_password]
        self.environ['query_data']['crypt_pw'] = ['False']
        authenticator.return_value = True

        app_factory.read_data(self.environ, MagicMock())

        SuperSimple.assert_called_with(escrow_data, ctype='application/octet-stream')

if __name__ == "__main__":
    unittest.main()












