import json
import unittest
from mock import sentinel, patch

from account_mgr import api_client


class TestApiClient(unittest.TestCase):
    @patch.object(api_client, 'VerifiedHTTPSHandler')
    def setUp(self, httpshandler):
        self.httpshandler = httpshandler.return_value
        self.response = self.httpshandler.https_open.return_value
        self.client = api_client.ApiClient(
            'https://example.com',
            sentinel.api_username,
            sentinel.api_password
        )

    def test_verifies_ssl_certificate(self):
        self.client.open('/')
        self.assertEqual(self.httpshandler.https_open.call_count, 1)

    @patch.object(api_client, 'RequestWithMethod')
    def test_logs_in_using_provided_credentials(self, req):
        self.client.open('/')
        req.assert_called_once_with(
            self.client.base + '/',
            None,
            {'authorization': (
                'Basic PFNlbnRpbmVsT2JqZWN0ICJhcGlfdXNlcm5hbWUiPjo8'
                'U2VudGluZWxPYmplY3QgImFwaV9wYXNzd29yZCI+'
            )}
        )

    def test_get_json(self):
        data = {'foo': 'bar'}
        self.response.read.return_value = json.dumps(data)
        self.assertEqual(self.client.get_json('/'), data)

    def test_post_json(self):
        postdata = {'foo': 'bar'}
        respdata = {'baz': 'qux'}
        self.response.read.return_value = json.dumps(respdata)
        self.assertEqual(self.client.post_json('/', postdata), respdata)
        ((req,), _) = self.httpshandler.https_open.call_args
        self.assertEqual(json.loads(req.data), postdata)

    def test_delete(self):
        self.client.delete('/')
        ((req,), _) = self.httpshandler.https_open.call_args
        self.assertEqual(req.get_method(), 'DELETE')

    def test_raises_HTTPError_on_error_responses(self):
        self.response.code = 409
        with self.assertRaises(api_client.urllib2.HTTPError):
            self.client.open('/')


if __name__ == '__main__':
    unittest.main()
