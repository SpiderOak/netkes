import os
import json
from base64 import b64decode, b64encode
import unittest
from mock import patch, Mock

from Crypto.PublicKey import RSA

os.environ['SPIDEROAK_ESCROW_LAYERS_PATH'] = ''
os.environ['SPIDEROAK_ESCROW_KEYS_PATH'] = ''
from key_escrow.server import read_escrow_data, _ESCROW_KEYS_CACHE

from Pandora import serial
serial.register(RSA._RSAobj)

import netkes_client


class TestNetkesClient(unittest.TestCase):
    def setUp(self):
        layer = serial.loads(
            'cereal1\n2\ndict\nCrypto.PublicKey.RSA._RSAobj\n6\nl65537L'
            '\ns1\nel572396271319355377302563592532289659494057533229597'
            '51710497474978922545181152759845508370178512234195180734902'
            '12419530396241354979963274248658624171029071725537151731993'
            '42933079891189457563201701117839696266295625152139367640601'
            '66443728541654900932569585341275738092423626919561311239635'
            '547176809158404659713L\ns1\ndl12728397948376965717385352254'
            '27139909550150941750411661187185470172925774815828047636767'
            '79872053348685177789877867582370921033415215069592981250085'
            '60556879090635468400999031563232300384449880853932718970353'
            '29805338834524020288467900702919724732303093984109904938853'
            '65647029509787184463935331239873911603698563L\ns1\nnl125577'
            '19737462719423110792947834292566930717591137982174999804751'
            '57426272766733316753566802241203955973889242142431112011040'
            '3860412744740476425917223401771L\ns1\nql1013591497061769252'
            '04895782750537719326038384264015503840615434274912532862261'
            '49765674778971387525351166395571997688812581139239675783599'
            '201065332383615753L\ns1\npl97225030816482359917484417766934'
            '30964287586773695586071056462460373031449533752987373837199'
            '72700016650629608621663588495627267552627999501333835100675'
            '9420L\ns1\nur0\nr1\n'
        )
        layer._randfunc = os.urandom
        self.layers = [('keyid', layer)]
        _ESCROW_KEYS_CACHE['keyid'] = layer

        self.sign_key = serial.loads(
            'cereal1\n2\ndict\nCrypto.PublicKey.RSA._RSAobj\n6\nl65537L'
            '\ns1\nel488998731920803595820925672497412329981375135192610'
            '84857389376383295791619483445264680079462203305484701008340'
            '57980910145198252592264933868738967927974809918625147286702'
            '92149399952343077067798254508626729649869563459616085824789'
            '31737856189011389458886653057704339590120539561170419572137'
            '549729675692397744513L\ns1\ndl13662819702376238599640179825'
            '40199175903367250815063829424764478185562881721558045835325'
            '02034209499980851380611211585482684966695148050379841211519'
            '90777846717237250189829960261537886730596610705749175213240'
            '29345221905361630262971841665103104788484983174076861127496'
            '93363485578857292553118398596402906394535309L\ns1\nnl125153'
            '92213883511393234180326019375584559651650302222103156776465'
            '77673640645230891483338041681039093600136032724891701279815'
            '4161197516362175629467657595419L\ns1\nql1091681304819186470'
            '75257045239424491842722017497241906220305724398464847269465'
            '01870670684745169890379365398342306412289577240231138208678'
            '788024638742440311L\ns1\npl43686597982280522901322472960701'
            '29738889210109581129368500126135091705488019320241792983277'
            '84798183272094286556009959784668608746730102217136755267929'
            '8862L\ns1\nur0\nr1\n'
        )
        self.sign_key._randfunc = os.urandom

    def _get_client_with_dummy_credentials(self):
        client = netkes_client.NetkesClient('url')
        client.brand = 'brand'
        client.username = 'username'
        client.password = 'password'
        client.challenge = 'challenge'
        client.challenge_b64 = b64encode(client.challenge)
        client.layers = self.layers
        return client

    @patch('netkes_client.RSA.generate')
    def test_get_auth_params(self, gen):
        gen.return_value = self.sign_key

        client = self._get_client_with_dummy_credentials()
        params = client.get_auth_params()
        auth = b64decode(params.pop('auth'))
        auth = json.loads(read_escrow_data('brand', auth, 1))

        self.assertEqual(auth, {
            'challenge': b64encode('challenge'),
            'password': 'password',
        })
        self.assertEqual(params, {
            'brand_id': 'brand',
            'username': 'username',
        })

    @unittest.skip('sign_key disabled')
    @patch('netkes_client.RSA.generate')
    def test_that_sign_key_has_no_priv_key(self, gen):
        gen.return_value = self.sign_key

        client = self._get_client_with_dummy_credentials()
        params = client.get_auth_params()
        sign_key = serial.loads(params['sign_key'])

        self.assertFalse(sign_key.has_private())
        with self.assertRaises(TypeError):
            sign_key.sign('x' * 32, 'x' * 32)

    @patch('netkes_client.requests.get')
    def test_login_without_verification(self, get):
        client = netkes_client.NetkesClient('url')

        get.return_value.json.return_value = {
            'layer_data': serial.dumps(self.layers).encode('base64'),
            'challenge': 'challenge'.encode('base64')
        }

        client.login('brand', 'username', 'password', False)

        self.assertEqual(get.call_args_list, [
            (
                (('url/authsession',),
                {'params': {'brand_id': 'brand', 'username': 'username'}})
            )
        ])

        self.assertEqual(client.brand, 'brand')
        self.assertEqual(client.username, 'username')
        self.assertEqual(client.password, 'password')
        self.assertEqual(client.layers, self.layers)
        self.assertEqual(client.challenge, 'challenge')
        self.assertEqual(client.challenge_b64, 'challenge'.encode('base64'))

    @patch('netkes_client.requests.get')
    def test_login_with_verification(self, get):
        client = netkes_client.NetkesClient('url')
        client.get_auth_params = Mock()

        get.return_value.json.return_value = {
            'layer_data': serial.dumps(self.layers).encode('base64'),
            'challenge': 'challenge'.encode('base64')
        }
        get.return_value.content = 'OK'

        client.login('brand', 'username', 'password')

        self.assertEqual(get.call_args_list, [
            (
                (('url/authsession',),
                {'params': {'brand_id': 'brand', 'username': 'username'}})
            ),
            (
                (('url/auth',),
                {'params': client.get_auth_params.return_value})
            ),
        ])

        self.assertEqual(client.brand, 'brand')
        self.assertEqual(client.username, 'username')
        self.assertEqual(client.password, 'password')
        self.assertEqual(client.layers, self.layers)
        self.assertEqual(client.challenge, 'challenge')
        self.assertEqual(client.challenge_b64, 'challenge'.encode('base64'))

    @patch('netkes_client.requests.post')
    @patch('netkes_client.bcrypt.kdf')
    def test_read_data(self, kdf, post):
        client = self._get_client_with_dummy_credentials()

        kdf.return_value = 'x' * netkes_client.SecretBox.KEY_SIZE
        nonce = 'x' * netkes_client.SecretBox.NONCE_SIZE
        box = netkes_client.SecretBox(kdf.return_value)
        boxed_data = box.encrypt('secrat data', nonce)
        post.return_value.content = boxed_data

        result = client.read_data('escrow data', self.sign_key)
        self.assertEqual(result, 'secrat data')

        kdf.assert_called_once_with(
            client.password.encode('utf-8'),
            client.challenge,
            netkes_client.SecretBox.KEY_SIZE,
            netkes_client.ITERATIONS
        )


if __name__ == '__main__':
    unittest.main()
