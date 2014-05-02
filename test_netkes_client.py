import os
import logging
import json
from base64 import b64decode, b64encode
import unittest
from mock import patch, Mock

from hashlib import md5
from Crypto.PublicKey import RSA

os.environ['SPIDEROAK_ESCROW_LAYERS_PATH'] = ''
os.environ['SPIDEROAK_ESCROW_KEYS_PATH'] = ''
from key_escrow.server import read_escrow_data, _ESCROW_KEYS_CACHE

from Pandora import serial
serial.register(RSA._RSAobj)

import netkes_client

logging.disable(logging.CRITICAL)


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
        self.layer_fingerprint = '4575-85F4-12DA-ADC7-231A-26AF-8F24-39FA'

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
        client.session = Mock()
        client.brand = 'brand'
        client.username = 'username'
        client.challenge = 'challenge'
        client.challenge_b64 = b64encode(client.challenge)
        client.layers = self.layers
        client.password = 'password'
        client.session_key = 'x' * netkes_client.SecretBox.KEY_SIZE
        return client

    def test_layer_fingerprint(self):
        client = netkes_client.NetkesClient('url')
        fingerprint = client._layer_fingerprint(self.layers)
        self.assertEqual(fingerprint, self.layer_fingerprint)

    @patch('netkes_client.requests.Session')
    def test_start_login(self, session):
        post = session.return_value.post
        post.return_value.json.return_value = {
            'layer_data': serial.dumps(self.layers).encode('base64'),
            'challenge': 'challenge'.encode('base64')
        }

        client = netkes_client.NetkesClient('url')
        fingerprint = client.start_login('brand', 'username')

        self.assertEqual(fingerprint, self.layer_fingerprint)

        post.assert_called_once_with(
            'url/authsession/',
            data={'brand_id': 'brand', 'username': 'username'}
        )
        self.assertEqual(client.brand, 'brand')
        self.assertEqual(client.username, 'username')
        self.assertEqual(client.layers, self.layers)
        self.assertEqual(client.challenge, 'challenge')
        self.assertEqual(client.challenge_b64, 'challenge'.encode('base64'))

    @patch('netkes_client.RSA.generate')
    def test_get_auth_data(self, gen):
        gen.return_value = self.sign_key

        client = self._get_client_with_dummy_credentials()
        auth_data = client._get_auth_data()
        auth = b64decode(auth_data.pop('auth'))
        auth = json.loads(read_escrow_data('brand', auth, 1))

        self.assertEqual(auth, {
            'challenge': b64encode('challenge'),
            'password': 'password',
        })
        self.assertEqual(auth_data, {
            'brand_id': 'brand',
            'username': 'username',
            'sign_key': serial.dumps(self.sign_key.publickey()),
            'layer_count': len(self.layers),
        })

    @patch('netkes_client.RSA.generate')
    def test_that_sign_key_has_no_priv_key(self, gen):
        gen.return_value = self.sign_key

        client = self._get_client_with_dummy_credentials()
        auth_data = client._get_auth_data()
        sign_key = serial.loads(auth_data['sign_key'])

        self.assertFalse(sign_key.has_private())
        with self.assertRaises(TypeError):
            sign_key.sign('x' * 32, 'x' * 32)

    @patch('netkes_client.bcrypt.kdf')
    def test_finish_login(self, kdf):
        client = self._get_client_with_dummy_credentials()
        client.password = None
        client.session_key = None
        client._get_auth_data = Mock()
        client.session.post.return_value.content = 'OK'

        client.finish_login('password')

        client.session.post.assert_called_once_with(
            'url/auth/',
            data=client._get_auth_data.return_value
        )

        kdf.assert_called_once_with(
            client.password.encode('utf-8'),
            client.challenge,
            netkes_client.SecretBox.KEY_SIZE,
            netkes_client.ITERATIONS
        )

        self.assertEqual(client.password, 'password')
        self.assertEqual(client.session_key, kdf.return_value)

    def test_finish_login_incorrect_credentials(self):
        client = self._get_client_with_dummy_credentials()
        client.password = None
        client.session_key = None
        client._get_auth_data = Mock()
        client.session.post.return_value.status_code = 403

        with self.assertRaises(client.IncorrectCredentialsError):
            client.finish_login('password')

        client.session.post.assert_called_once_with(
            'url/auth/',
            data=client._get_auth_data.return_value
        )

    def test_read_data(self):
        client = self._get_client_with_dummy_credentials()
        post = client.session.post

        nonce = 'x' * netkes_client.SecretBox.NONCE_SIZE
        box = netkes_client.SecretBox(client.session_key)
        boxed_data = box.encrypt('secrat data', nonce)
        post.return_value.content = boxed_data

        result = client.read_data('escrow data', self.sign_key)
        self.assertEqual(result, 'secrat data')

    def test_logged_in_returns_False_when_login_not_started(self):
        client = netkes_client.NetkesClient('url')
        self.assertFalse(client.logged_in())

    @patch('netkes_client.requests.Session')
    def test_logged_in_returns_False_when_login_not_finished(self, session):
        post = session.return_value.post
        post.return_value.json.return_value = {
            'layer_data': serial.dumps(self.layers).encode('base64'),
            'challenge': 'challenge'.encode('base64')
        }

        client = netkes_client.NetkesClient('url')
        client.start_login('brand', 'username')

        self.assertFalse(client.logged_in())

    @patch('netkes_client.bcrypt.kdf')
    @patch('netkes_client.requests.Session')
    def test_logged_in_returns_True_when_logged_in(self, session, kdf):
        post = session.return_value.post
        post.return_value.json.return_value = {
            'layer_data': serial.dumps(self.layers).encode('base64'),
            'challenge': 'challenge'.encode('base64')
        }
        post.return_value.content = 'OK'

        client = netkes_client.NetkesClient('url')
        client._get_auth_data = Mock()

        client.start_login('brand', 'username')
        client.finish_login('password')

        self.assertTrue(client.logged_in())

    def test_read_data_fails_when_not_logged_in(self):
        client = netkes_client.NetkesClient('url')
        client.logged_in = Mock()
        client.logged_in.return_value = False
        with self.assertRaises(client.NotLoggedInError):
            client.read_data('escrow data', self.sign_key)


if __name__ == '__main__':
    unittest.main()
