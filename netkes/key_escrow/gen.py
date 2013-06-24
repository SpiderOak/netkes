import os
import time
import random
import hmac
from hashlib import sha256

from Crypto.PublicKey import RSA

GEN_COUNTER = 1

_hmac_key = '\x91\xc3\x94\xb2\xc7\xa4\xf6\xf8;n\x8a\xb1r{&\xf0.m\x97L\xab\x174\r\r\x92\x9c\xf4}\x9dp\xc7'

def new_key_id():
    "create new unique key ID"
    global GEN_COUNTER
    timestamp = time.strftime("%Y%m%d%H%M%S", time.localtime())
    key_id = "%s-%d-%d" % ( timestamp, GEN_COUNTER, random.randint(1, 99999), )
    key_hmac_digest = hmac.new(_hmac_key, key_id, sha256).hexdigest()
    GEN_COUNTER += 1
    return key_id + key_hmac_digest
    

def make_keypair(size=3072):
    "return Key ID string, keypair obj"
    rsakey = RSA.generate(size, os.urandom)
    return new_key_id(), rsakey
