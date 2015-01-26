import os

from key_escrow.write import make_escrow_layer
from key_escrow.read import read_escrow_layer
from key_escrow.gen import make_keypair

_TEST_LAYERS = 500
_TEST_DATA_SIZE = 4097

def test_write_and_read_layers():
    """
    test encapsulating data in many escrow layers and reading it back out
    """

    userkey = make_keypair()

    layers = list()
    for _ in range(_TEST_LAYERS): 
        layers.append(make_keypair())

    # this is the data that goes in the innermost layer
    data = os.urandom(_TEST_DATA_SIZE)

    layer_data = data

    # we encapsulate this data in layers of key escrow
    for idx, layer in enumerate(layers):
        cipher_layer_data = make_escrow_layer(
            layer[0], layer[1].publickey(), layer_data, userkey[1])

        # at every layer we test that we can read back the data
        plain_layer_data = read_escrow_layer(
            { layer[0]: layer[1] }, cipher_layer_data, userkey[1].publickey())
        assert plain_layer_data == layer_data, \
            "readback fail at layer %d" % (idx + 1)

        layer_data = cipher_layer_data


    # read back the layers in reverse
    for idx, layer in enumerate(layers[::-1]):
        plain_layer_data = read_escrow_layer(
            { layer[0]: layer[1] }, layer_data, userkey[1].publickey())
        layer_data = plain_layer_data

    # we should get our original data back out
    assert layer_data == data

    return True

def test_all():
    assert test_write_and_read_layers()
    print("All tests complete")

if __name__ == "__main__":
    test_all()
