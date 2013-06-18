import os
import time
import json
import zlib
import struct
from binascii import b2a_base64, a2b_base64
from hashlib import sha256
import hmac

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes

AES_KEY_SIZE = 32
AES_NONCE_SIZE = 16

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
    
