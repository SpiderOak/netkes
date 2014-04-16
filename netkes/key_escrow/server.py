import os
from Crypto import Random
from key_escrow.read import read_escrow_layer

from Pandora.serial import load

_ESCROW_LAYERS_PATH = os.environ["SPIDEROAK_ESCROW_LAYERS_PATH"]
_ESCROW_KEYS_PATH = os.environ["SPIDEROAK_ESCROW_KEYS_PATH"]

_ESCROW_LAYERS_CACHE = dict()
_ESCROW_KEYS_CACHE = dict()


def get_escrow_layers(brand_identifier):
    """
    Return a binary string containing a serilization of escrow key layers

    The de-serialized structure will be a list of tulpes of the form: 
        (key id, public key, )

    The first item in the list is the innermost escrow layer (to which
    plaintext data is first enciphered.)
    """

    if brand_identifier in _ESCROW_LAYERS_CACHE:
        return _ESCROW_LAYERS_CACHE[brand_identifier]

    filepath = os.path.join(_ESCROW_LAYERS_PATH, 
        "brand.%s.layers.serial" % (brand_identifier, ))

    with open(filepath, "rb") as fobj:
        data = fobj.read()

    _ESCROW_LAYERS_CACHE[brand_identifier] = data

    return data
    
def load_escrow_key_cache():
    """
    populate escrow key cache with everything in SPIDEROAK_ESCROW_KEYS_PATH
    """
    #print "loading keys in %s" % _ESCROW_KEYS_PATH

    # TODO perhaps memcache this w/ short (30m?) expire.

    for name in os.listdir(_ESCROW_KEYS_PATH):
        if not name.endswith(".key"):
            continue

        filename_key_id = name[0:-4] 
        if filename_key_id in _ESCROW_KEYS_CACHE:
            continue

        keypath = os.path.join(_ESCROW_KEYS_PATH, name)
        with open(keypath, "rb") as fobj:
            key_id, key = load(fobj)
            assert filename_key_id == key_id
            key._randfunc = Random.new().read
            _ESCROW_KEYS_CACHE[key_id] = key
            #print "Loaded %s" % key_id

    return True

def read_escrow_data(brand_identifier, escrowed_data, layer_count=2, 
                     sign_key=None, _recur=0):
    """
    escrowed_data = binary data encoded to escrow keys
    sign_key = user's public key used to check signatures (optional)
    layer_count = number of layers to go through (2 by default)

    returns: plaintext escrowed data
    """
    # TODO: make this talk to a remote key escrow service hardened/isolated by
    # policy

    layer_data = escrowed_data

    try: 
        for layer_idx in range(layer_count):
            layer_data = read_escrow_layer(
                _ESCROW_KEYS_CACHE, layer_data, sign_key)
    except KeyError, err:
        if not "Key not available for ID" in str(err):
            raise
        if _recur:
            raise
        load_escrow_key_cache()
        return read_escrow_data(brand_identifier, escrowed_data, 
            layer_count=layer_count, sign_key=sign_key, _recur=_recur+1)

    return layer_data

