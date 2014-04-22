import unittest
from mock import Mock, MagicMock, sentinel, patch

patch('wsgi_util.post_util.read_querydata', lambda x: x).start()
patch('wsgi_util.post_util.read_postdata', lambda x: x).start()
from netkes.netkes_agent import app_factory

@patch('netkes.netkes_agent.app_factory.server.read_escrow_data')
@patch('netkes.netkes_agent.app_factory.serial.loads')
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
    def test_authentication_required(self, BadRequest, loads, read_escrow_data):
        app_factory.read_data(self.environ, MagicMock())
        self.assertTrue(BadRequest.called)

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

if __name__ == "__main__":
    unittest.main()












