import unittest
from mock import MagicMock, sentinel, patch
from datetime import datetime, timedelta

import account_mgr


class TestAdminAuth(unittest.TestCase):
    def setUp(self):
        account_mgr.get_cursor = MagicMock()
        cur = MagicMock()
        account_mgr.get_cursor.return_value = cur
        self.cur = cur.__enter__()
        account_mgr.get_api = MagicMock()
        self.api = MagicMock()
        account_mgr.get_api.return_value = self.api
        self.user = {
            'avatar_id': sentinel.avatar_id,
            'email': sentinel.email,
        }
        self.api.get_user.return_value = self.user
        self.time = datetime.now() + timedelta(hours=1)

    @patch('account_mgr.user_source.ldap_source')
    def test_user_disabled(self, ldap_source):
        ldap_source.can_auth.return_value = True
        self.cur.rowcount = 0
        self.user['enabled'] = False
        self.assertFalse(
            account_mgr.authenticator({'auth_method': 'ldap', }, 'test', 'pass')
        )

    @patch('account_mgr.user_source.ldap_source')
    def test_user_enabled(self, ldap_source):
        ldap_source.can_auth.return_value = True
        self.cur.rowcount = 0
        self.user['enabled'] = True
        self.assertTrue(
            account_mgr.authenticator({'auth_method': 'ldap', }, 'test', 'pass')
        )

    def test_no_restrictions(self):
        self.cur.rowcount = 1
        self.cur.fetchone.return_value = (False, False, self.time, False)
        self.api.list_devices.return_value = []
        self.assertTrue(
            account_mgr.admin_token_auth(
                {}, self.user, sentinel.username, sentinel.password)
        )

    def test_bad_credentials(self):
        self.cur.rowcount = 0
        self.assertFalse(
            account_mgr.admin_token_auth(
                {}, self.user, sentinel.username, sentinel.password)
        )

    def test_no_devices_only(self):
        self.cur.rowcount = 1
        self.cur.fetchone.return_value = (True, False, self.time, False)
        self.api.list_devices.return_value = [1]
        self.assertFalse(
            account_mgr.admin_token_auth(
                {}, self.user, sentinel.username, sentinel.password)
        )
        self.cur.fetchone.return_value = (True, False, self.time, False)
        self.api.list_devices.return_value = []
        self.assertTrue(
            account_mgr.admin_token_auth(
                {}, self.user, sentinel.username, sentinel.password)
        )

    def test_single_use_only(self):
        self.cur.rowcount = 1
        self.cur.fetchone.return_value = (False, True, self.time, True)
        self.api.list_devices.return_value = []
        self.assertFalse(
            account_mgr.admin_token_auth(
                {}, self.user, sentinel.username, sentinel.password)
        )
        self.cur.fetchone.return_value = (False, True, self.time, False)
        self.api.list_devices.return_value = []
        self.assertTrue(
            account_mgr.admin_token_auth(
                {}, self.user, sentinel.username, sentinel.password)
        )

if __name__ == '__main__':
    unittest.main()
