import os
import time
import json
import zlib
import struct
import logging
from binascii import b2a_base64, a2b_base64
from hashlib import sha256

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes

AES_KEY_SIZE = 32
AES_NONCE_SIZE = 16

def read_escrow_layer(escrow_keys, layer_data, sign_key=None):
    """
    inverse of make_escrow_layer

    escrow_keys = dictionary of available private escrow keys in the format
        key_id = key object
    layer_data = binary output from make_escrow_layer
    sign_key = public key of the user who has signed this layer
    """

    log = logging.getLogger("read_escrow_layer") 
    header_format = "!HHHL"
    header_size = struct.calcsize(header_format)

    if not len(layer_data) > header_size:
        raise ValueError(
            "Layer too small: expected >%d bytes" % ( header_size, ))

    ( key_id_len, sig_hmac_len, sig_len, payload_len, ) = struct.unpack(
        header_format, layer_data[0:header_size])

    expected_size = header_size + sum(
        (key_id_len, sig_hmac_len, sig_len, payload_len, ))

    if not len(layer_data) == expected_size:
        raise ValueError(
            "Layer wrong sized: expected %d but %d" % ( 
            expected_size, len(layer_data), ))

    body_format = "!%ds%ds%ds%ds" % ( 
            key_id_len, sig_hmac_len, sig_len, payload_len, )

    ( key_id, sig_hmac, sig, payload, ) = struct.unpack(
        body_format, layer_data[header_size:])

    if not key_id in escrow_keys:
        raise KeyError("Key not available for ID %r" % (key_id, ))

    if sign_key is not None: 
        valid = sign_key.verify(sig_hmac, (bytes_to_long(sig), ))
        if not valid:
            log.warn("Signature error: sig_hmac=%r sig=%r", sig_hmac, sig)
            raise ValueError("Signature error")

    payload_data = json.loads(zlib.decompress(payload))
    for k, v in payload_data.iteritems():
        payload_data[k] = a2b_base64(v)

    priv_key = escrow_keys[key_id]
    aes_key = priv_key.decrypt(payload_data['aes_key'])


    if not len(aes_key) == AES_KEY_SIZE:
        aes_key = sha256(aes_key).digest()
    if not len(payload_data['aes_iv']) == AES_NONCE_SIZE:
        raise ValueError("aes_iv wrongsized")

    aes = AES.new(aes_key, AES.MODE_CFB, 
        payload_data['aes_iv'])
    data = aes.decrypt(payload_data['data'])

    return data
