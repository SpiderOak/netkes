import unittest
from mock import Mock, MagicMock, sentinel, patch

import account_mgr

class TestAdminTokenAuth(unittest.TestCase):
    def setUp(self):
        account_mgr.get_cursor = MagicMock()
        cur = MagicMock()
        account_mgr.get_cursor.return_value = cur 
        self.cur = cur.__enter__()
        account_mgr.get_api = MagicMock()
        self.api = MagicMock()
        account_mgr.get_api.return_value = self.api 

    def test_no_restrictions(self):
        self.cur.rowcount = 1
        self.cur.fetchone.return_value = (False, False, False)
        self.api.list_devices.return_value = []
        self.assertTrue(
            account_mgr.admin_token_auth({}, 
                                         sentinel.username, 
                                         sentinel.password)
        )

    def test_bad_credentials(self):
        self.cur.rowcount = 0 
        self.assertFalse(
            account_mgr.admin_token_auth({}, 
                                         sentinel.username, 
                                         sentinel.password)
        )

    def test_no_devices_only(self):
        self.cur.rowcount = 1
        self.cur.fetchone.return_value = (True, False, False)
        self.api.list_devices.return_value = [1]
        self.assertFalse(
            account_mgr.admin_token_auth({}, 
                                         sentinel.username, 
                                         sentinel.password)
        )
        self.cur.fetchone.return_value = (True, False, False)
        self.api.list_devices.return_value = []
        self.assertTrue(
            account_mgr.admin_token_auth({}, 
                                         sentinel.username, 
                                         sentinel.password)
        )

    def test_single_use_only(self):
        self.cur.rowcount = 1
        self.cur.fetchone.return_value = (False, True, True)
        self.api.list_devices.return_value = []
        self.assertFalse(
            account_mgr.admin_token_auth({}, 
                                         sentinel.username, 
                                         sentinel.password)
        )
        self.cur.fetchone.return_value = (False, True, False)
        self.api.list_devices.return_value = []
        self.assertTrue(
            account_mgr.admin_token_auth({}, 
                                         sentinel.username, 
                                         sentinel.password)
        )
if __name__ == '__main__':
    unittest.main()
