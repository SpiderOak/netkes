import unittest

from netkes_agent import config_mgr

_config_test_file = "test.json"
_tmp_config_test = "tmptest.json"

class TestReadConfiguration(unittest.TestCase):
    def test_successful_read_withkey(self):
        mgr = config_mgr.ConfigManager(_config_test_file)

        self.assertEqual(mgr.config['testkey_1'],
                         'testvalue_1_deadbeef')

    def test_successful_read_nokey(self):
        mgr = config_mgr.ConfigManager(_config_test_file)

        with self.assertRaises(KeyError):
            throwaway = mgr.config['testkey_deadbeef']

    def test_failed_read(self):
        with self.assertRaises(IOError):
            mgr = config_mgr.ConfigManager('DEADBEEF')


class TestSetConfiguration(unittest.TestCase):
    def setUp(self):
        self.mgr = config_mgr.ConfigManager(_config_test_file)

    def test_set_new_data(self):
        self.mgr.config['test_newvalue'] = 'DEADBEEFERY'
        
        self.assertEqual(self.mgr.config['test_newvalue'], 'DEADBEEFERY')

    def test_set_apply_new_data(self):
        self.mgr.config['test_newvalue'] = 'DEADBEEF_2'
        
if __name__ == "__main__":
    unittest.main()
