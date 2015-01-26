import unittest
from mock import Mock, MagicMock, sentinel, patch

import json

from directory_agent import api_interface

class MockException(Exception):
    pass

class TestRunApiCall(unittest.TestCase):
    def setUp(self):
        self.url_patcher = patch("urllib.urlopen")
        self.urlopen = self.url_patcher.start()

        urlfile = MagicMock(spec=file)
        self.test_return_data = { "testkey1": "testvalue1",
                             "testkey2": 2
                             }
        urlfile.read.return_value = json.dumps(self.test_return_data)
        self.urlopen.return_value = urlfile

    def tearDown(self):
        self.url_patcher.stop()

    def test_successful_read_nodata(self):
        self.assertEqual(api_interface._run_api_call(str(sentinel.api_root),
                                                     str(sentinel.action)),
                         self.test_return_data)

        args, _ = self.urlopen.call_args
        assert len(args) == 1

    def test_successful_read_withdata(self):
        test_send_data = {"testsend1": "testvalues1",
                          "testsend2": "testvalues2",
                          }
        self.assertEqual(api_interface._run_api_call(str(sentinel.api_root),
                                                     str(sentinel.action),
                                                     test_send_data),
                         self.test_return_data)
        args, _ = self.urlopen.call_args
        assert len(args) == 2
        self.assertEqual(args[1], json.dumps(test_send_data))

    def test_blows_up_with_bad_json_returned(self):
        urlfile = MagicMock(spec=file)
        urlfile.read.return_value = "DEADBEEF"
        self.urlopen.return_value = urlfile

        with self.assertRaises(ValueError):
            api_interface._run_api_call(str(sentinel.api_root),
                                        str(sentinel.action))

    def test_blows_up_with_bad_data_given(self):
        with self.assertRaises(TypeError):
            api_interface._run_api_call(str(sentinel.api_root),
                                        str(sentinel.action),
                                        sentinel.bad_obj)

    def test_gets_url_read_exceptions(self):
        def side_effect():
            raise Exception("DEADBEEF")

        urlfile = MagicMock(spec=file)        
        urlfile.read.side_effect = side_effect
        self.urlopen.return_value = urlfile

        with self.assertRaises(Exception) as cm:
            api_interface._run_api_call(str(sentinel.api_root),
                                        str(sentinel.action))
                         
        the_exception = cm.exception
        self.assertEqual(str(the_exception), "DEADBEEF")

    def test_gets_url_open_exceptions(self):
        self.urlopen.side_effect = Exception("DEADBEEF")

        with self.assertRaises(Exception) as cm:
            api_interface._run_api_call(str(sentinel.api_root),
                                        str(sentinel.action))
                         
        the_exception = cm.exception
        self.assertEqual(str(the_exception), "DEADBEEF")


class TestDeactivateUsers(unittest.TestCase):
    def setUp(self):
        self.run_api_patcher = patch("directory_agent.api_interface._run_api_call")
        self.run_api_call = self.run_api_patcher.start()
        self.test_user = {'avatar_id': 1001}

    def tearDown(self):
        self.run_api_patcher.stop()

    def test_deactivate_succeeds(self):
        ret_val = {"success" : True}
        self.run_api_call.return_value = ret_val

        self.assertEqual(api_interface.deactivate_user(sentinel.api_root,
                                                       self.test_user),
                         ret_val)
        

    def test_deactivate_fails(self):
        ret_val = {"success" : False,
                   "reason"  : "DEADBEEF",
                   }
        self.run_api_call.return_value = ret_val

        with self.assertRaises(api_interface.ManipulateUserFailed) as cm:
            retval = api_interface.deactivate_user(sentinel.api_root,
                                                   self.test_user)

        the_exception = cm.exception
        self.assertEqual(str(the_exception), "DEADBEEF")


    def test_deactivate_connection_problem(self):
        self.run_api_call.side_effect = MockException("DEADBEEF")

        with self.assertRaises(api_interface.ManipulateUserFailed) as cm:
            retval = api_interface.deactivate_user(sentinel.api_root,
                                                   self.test_user)

        the_exception = cm.exception
        self.assertEqual(str(the_exception), "DEADBEEF")


class TestPurgeUser(unittest.TestCase):
    def setUp(self):
        self.run_api_patcher = patch("directory_agent.api_interface._run_api_call")
        self.run_api_call = self.run_api_patcher.start()
        self.test_user = {'avatar_id': 1001}

    def tearDown(self):
        self.run_api_patcher.stop()

    def test_purge_succeeds(self):
        ret_val = {"success" : True}
        self.run_api_call.return_value = ret_val

        self.assertEqual(api_interface.purge_user(sentinel.api_root,
                                                  self.test_user),
                         ret_val)
        

    def test_purge_fails(self):
        ret_val = {"success" : False,
                   "reason"  : "DEADBEEF",
                   }
        self.run_api_call.return_value = ret_val

        with self.assertRaises(api_interface.ManipulateUserFailed) as cm:
            retval = api_interface.purge_user(sentinel.api_root,
                                              self.test_user)

        the_exception = cm.exception
        self.assertEqual(str(the_exception), "DEADBEEF")


    def test_purge_connection_problem(self):
        self.run_api_call.side_effect = MockException("DEADBEEF")

        with self.assertRaises(api_interface.ManipulateUserFailed) as cm:
            retval = api_interface.purge_user(sentinel.api_root,
                                              self.test_user)

        the_exception = cm.exception
        self.assertEqual(str(the_exception), "DEADBEEF")
        
class TestFetchUsers(unittest.TestCase):
    def setUp(self):
        self.run_api_patcher = patch("directory_agent.api_interface._run_api_call")
        self.run_api_call = self.run_api_patcher.start()

    def tearDown(self):
        self.run_api_patcher.stop()

    def test_fetch_list_empty_succeeds(self):
        ret_val = []

        self.run_api_call.return_value = ret_val

        result = api_interface.fetch_users(Mock())
        self.assertEqual(result, ret_val)
        
    def test_fetch_list_succeeds(self):
        ret_val = [{'avatar_id': sentinel.avatar_id1,
                    'username' : sentinel.username1,
                    },
                   {'avatar_id': sentinel.avatar_id2,
                    'username' : sentinel.username2
                    }]

        self.run_api_call.return_value = ret_val

        result = api_interface.fetch_users(Mock())
        self.assertEqual(result, ret_val)

    def test_fetch_list_fails(self):
        self.run_api_call.side_effect = Exception("DEADBEEF")

        with self.assertRaises(api_interface.FetchInformationFailed) as cm:
            api_interface.fetch_users(Mock())

        the_exception = cm.exception
        self.assertEqual(str(the_exception), "DEADBEEF")

class TestFetchPlans(unittest.TestCase):
    def setUp(self):
        self.run_api_patcher = patch("directory_agent.api_interface._run_api_call")
        self.run_api_call = self.run_api_patcher.start()

    def tearDown(self):
        self.run_api_patcher.stop()

    def test_fetch_plans_empty_fails(self):
        ret_val = []

        self.run_api_call.return_value = ret_val

        with self.assertRaises(api_interface.FetchInformationFailed) as cm:
            result = api_interface.fetch_plans(Mock())

        the_exception = cm.exception
        self.assertEqual(str(the_exception), api_interface.NO_PLANS)
        
    def test_fetch_list_succeeds(self):
        ret_val = [{'group_id': sentinel.group_id1,
                    'storage_gigs' : sentinel.storage_gigs1,
                    },
                   {'group_id': sentinel.group_id2,
                    'storage_gigs' : sentinel.storage_gigs2
                    }]

        self.run_api_call.return_value = ret_val

        result = api_interface.fetch_plans(Mock())
        self.assertEqual(result, ret_val)

    def test_fetch_list_fails(self):
        self.run_api_call.side_effect = Exception("DEADBEEF")

        with self.assertRaises(api_interface.FetchInformationFailed) as cm:
            api_interface.fetch_plans(Mock())

        the_exception = cm.exception
        self.assertEqual(str(the_exception), "DEADBEEF")

class TestSetUserPlan(unittest.TestCase):
    def setUp(self):
        self.run_api_patcher = patch("directory_agent.api_interface._run_api_call")
        self.run_api_call = self.run_api_patcher.start()
        self.test_user = {'avatar_id': 1001,
                          'group_id'  : sentinel.group_id}

    def tearDown(self):
        self.run_api_patcher.stop()

    def test_planset_success_nopromo(self):
        ret_val = {'success': True}
        self.run_api_call.return_value = ret_val

        self.assertEqual(api_interface.set_user_plan(sentinel.api_root,
                                                     self.test_user),
                         ret_val)

        args, _ = self.run_api_call.call_args
        assert len(args) == 3
        self.assertIs(args[0], sentinel.api_root)
        self.assertIs(args[2]['group_id'], sentinel.group_id)

    def test_planset_success_promo(self):
        ret_val = {'success': True}
        self.run_api_call.return_value = ret_val

        self.assertEqual(api_interface.set_user_plan(sentinel.api_root,
                                                     self.test_user,
                                                     sentinel.promo_code),
                         ret_val)

        args, _ = self.run_api_call.call_args
        assert len(args) == 3
        self.assertIs(args[2]['promo_code'], sentinel.promo_code)

    def test_planset_failure(self):
        ret_val = {'success' : False,
                   'reason'  : "DEADBEEF",
                   }
        self.run_api_call.return_value = ret_val

        with self.assertRaises(api_interface.ManipulateUserFailed) as cm:
            res = api_interface.set_user_plan(sentinel.api_root,
                                              self.test_user)

        the_exception = cm.exception
        self.assertEqual(str(the_exception), "DEADBEEF")

    def test_planset_exception(self):
        self.run_api_call.side_effect = MockException("DEADBEEF")
        
        with self.assertRaises(api_interface.ManipulateUserFailed) as cm:
            res = api_interface.set_user_plan(sentinel.api_root,
                                              self.test_user)

        the_exception = cm.exception
        self.assertEqual(str(the_exception), "DEADBEEF")

class TestCreateUser(unittest.TestCase):
    def setUp(self):
        self.run_api_patcher = patch("directory_agent.api_interface._run_api_call")
        self.run_api_call = self.run_api_patcher.start()

    def tearDown(self):
        self.run_api_patcher.stop()

    def test_create_succeeds(self):
        self.run_api_call.return_value = {'success': True,
                                          'server_generated_username': sentinel.testuser}

        testuser = {'email': sentinel.email,
                    'firstname': sentinel.givenName,
                    'lastname': sentinel.surname,
                    }
        result = api_interface.create_user(sentinel.api_root,testuser)
                                           
        self.assertEqual(result['server_generated_username'], sentinel.testuser)

        args, _ = self.run_api_call.call_args

        self.assertIs(sentinel.api_root, args[0])
        assert sentinel.email in list(args[2].values())
        assert sentinel.givenName in list(args[2].values())
        assert sentinel.surname in list(args[2].values())

    def test_create_run_api_call_exception(self):
        self.run_api_call.side_effect = Exception("DEADBEEF")

        testuser = {'email': sentinel.email,
                    'firstname': sentinel.givenName,
                    'lastname': sentinel.surname,
                    }

        with self.assertRaises(api_interface.ManipulateUserFailed) as cm:
            api_interface.create_user(sentinel.api_root,testuser)
                                      
        the_exception = cm.exception
        self.assertEqual(str(the_exception), "DEADBEEF")

    def test_create_user_add_failed(self):
        self.run_api_call.return_value = {'success' : False,
                                          'reason'  : "Mocked it up to fail, duh!",
                                          }

        testuser = {'email': sentinel.email,
                    'firstname': sentinel.givenName,
                    'lastname': sentinel.surname,
                    }
        with self.assertRaises(api_interface.ManipulateUserFailed):
            api_interface.create_user(sentinel.api_root,
                                      testuser)

if __name__ == "__main__":
    unittest.main()
