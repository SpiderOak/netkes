"""
base layer of escrow is always ourselves - so that we are not trusting escrow
agents with data they can read.

"""

import os
import time
import shutil

from key_escrow.gen import make_keypair
from key_escrow.write import escrow_binary

from Pandora.serial import load, dump, register_all

_ESCROW_LAYERS_PATH = os.environ["SPIDEROAK_ESCROW_LAYERS_PATH"]
_ESCROW_KEYS_PATH = os.environ["SPIDEROAK_ESCROW_KEYS_PATH"]

class EscrowError(Exception): pass

def save_key(key_id, keypair):
    """
    save (key id, keypair, ) for key id
    """
    key_fn = os.path.join(_ESCROW_KEYS_PATH, "%s.key" % (key_id, ))
    with open(key_fn, "ab") as fobj:
        dump((key_id, keypair, ), fobj)
    print "Saved %s to %s" % ( key_id, key_fn, )

    return True

def load_keypair(key_id):
    "load and return keypair for key id"
    key_fn = os.path.join(_ESCROW_KEYS_PATH, "%s.key" % (key_id, ))
    with open(key_fn, "rb") as fobj:
        stored_key_id, keypair = load(fobj)
        assert key_id == stored_key_id

    return keypair

def read_config(name):
    """
    return value from named config file
    """
    cfg_fn = os.path.join(_ESCROW_KEYS_PATH, "%s.cfg" % name)
    with open(cfg_fn) as fobj:
        return fobj.readline().strip()

def write_config(name, value):
    "write value to named config file"
    cfg_fn = os.path.join(_ESCROW_KEYS_PATH, "%s.cfg" % name)
    if os.path.exists(cfg_fn):
        raise EscrowError("config %s already exists" % name)
    with open(cfg_fn, "wb") as fobj:
        fobj.write("%s\n" % (value, ))

    return True

def get_base():
    "return (base key ID, keypair,) for base layer"

    base_id = read_config("base")

    keypair = load_keypair(base_id)

    return base_id, keypair

def create_base():
    """
    Run only once to create base layer of key escrow (which is kept internal.)

    create a new (key_id, keypair, ) and save it.
    create a new file base.cfg with key_id in first line
    """

    base_id, base_keypair = make_keypair()

    save_key(base_id, base_keypair)

    write_config("base", base_id)

    print "base key ID %s and cfg saved" % ( base_id, )

    return True

def setup_brand(brand_identifier):
    """
    create keys, brand config file, and brand layers file for NUS
    """
    base_id, base_keypair = get_base()

    brand_id, brand_keypair = make_keypair()

    save_key(brand_id, brand_keypair)

    layers = ( (brand_id, brand_keypair.publickey(), ),
               (base_id,  base_keypair.publickey(),  ), )
        
    layer_fn = os.path.join(_ESCROW_LAYERS_PATH, 
        "brand.%s.layers.serial" % ( brand_identifier, ))

    if os.path.exists(layer_fn):
        raise EscrowError("Brand id %s layers exist" % (brand_identifier, ))
    with open(layer_fn, "ab") as fobj:
        dump(layers, fobj)

    write_config("brand.%s" % (brand_identifier, ), brand_id)

    print "new keys and config saved for brand %s" % brand_identifier

    return brand_id, brand_identifier, layers

def test_base():
    "test creating and reading base cfg and key"
    create_base()
    base_id, keypair = get_base()
    assert keypair.__class__.__name__ == "RSAobj"
    print "test base ok"
    return True

def test_setup_brand():
    from key_escrow.server import read_escrow_data
    brand_identifier = 'my_test_brand'
    brand_id, _brand_keypair, layers = setup_brand(brand_identifier)

    assert brand_id == layers[0][0]

    _user_key_id, user_keypair = make_keypair()
    test_data = "0123456789"
    escrowed_data = escrow_binary(layers, test_data, user_keypair)
    plain_escrowed_data = read_escrow_data(brand_identifier, escrowed_data, 
        sign_key=user_keypair.publickey())
    assert plain_escrowed_data == test_data

    print "setup brand test ok"
    return True

def test_all():
    "run all tests"
    global _ESCROW_KEYS_PATH 
    global _ESCROW_LAYERS_PATH
    test_dir = "/tmp/key_escrow_admin_test.%s" % ( time.time(), )
    try:
        _ESCROW_KEYS_PATH = os.path.join(test_dir, "keys")
        _ESCROW_LAYERS_PATH = os.path.join(test_dir, "layers")
        os.environ["SPIDEROAK_ESCROW_LAYERS_PATH"] = _ESCROW_LAYERS_PATH
        os.environ["SPIDEROAK_ESCROW_KEYS_PATH"] = _ESCROW_KEYS_PATH
        os.makedirs(_ESCROW_KEYS_PATH)
        os.makedirs(_ESCROW_LAYERS_PATH)
        test_results = []
        test_results.append(test_base())
        test_results.append(test_setup_brand())
        assert all(test_results)
    finally:
        shutil.rmtree(test_dir)

def run_as_utility():
    register_all()
    import sys
    if "testall" in sys.argv:
        test_all()
        return

    if "create_base" in sys.argv:
        create_base()
    elif "setup_brand" in sys.argv:
        brand_identifier = sys.argv[sys.argv.index('setup_brand') + 1]
        setup_brand(brand_identifier)
    else:
        print >>sys.stderr, "I don't know what you want me to do!"

    print >>sys.stderr, "IF YOU HAVE CREATED NEW KEYS, BACK THEM UP NOW!"    

if __name__ == "__main__":
    run_as_utility()

#def setup_escrow_agent(agent_name):
#    """
#    """
#    pass
#
#
#def setup_brand(brand_identifier, agent_name=None):
#    """
#    """
#    pass
#
#
#def get_agent(agent_name):
#    "return (ID, keypair,) for specified agent layer escrow"
#
#    agent_cfg = "agent.%s.cfg" % (agent_name, )
#    agent_key_id = read_config(agent_cfg)
#    keypair = load_key(agent_key_id)
#
#    return agent_key_id, keypair
#    
#
#
#
#
#
#
#
