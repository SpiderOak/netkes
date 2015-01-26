import unittest
from mock import Mock, mocksignature, sentinel, patch

import copy

from directory_agent import group_manager, api_interface

class TestApiCreateUsers(unittest.TestCase):
    def setUp(self):
        self.api_iface_create_patcher = patch("directory_agent.api_interface.create_user")
        self.api_iface_create = self.api_iface_create_patcher.start()

        self.api_iface_plan_patcher = patch("directory_agent.api_interface.set_user_plan")
        self.api_iface_setplan = self.api_iface_plan_patcher.start()

    def tearDown(self):
        self.api_iface_create_patcher.stop()
        self.api_iface_plan_patcher.stop()

    def test_create_no_users(self):
        config = Mock()
        users = []

        self.assertEqual(group_manager._api_create_users(config, users),
                         [])
    
    def test_create_one_user(self):
        config = Mock()
        users = [{'uniqueid' : sentinel.uniqueid,
                  'email'    : sentinel.email,
                  'firstname': sentinel.firstname,
                  'lastname' : sentinel.lastname,
                  'plan_id'  : sentinel.plan_id,
                  }]

        server_ok = {'success'   : True,
                     'avatar_id' : sentinel.avatar_id,
                     'account_id': sentinel.account_id,
                     'server_assigned_password': sentinel.server_assigned_password,
                     }
        self.api_iface_create.return_value = server_ok

        results = group_manager._api_create_users(config, users)

        self.assertEqual(len(results), 1)
        self.assertIs(results[0]['uniqueid'], sentinel.uniqueid)
        self.assertIs(results[0]['avatar_id'], sentinel.avatar_id)

    def test_create_many_users(self):
        config = Mock()
        
        users = [{'uniqueid' : sentinel.uniqueid1,
                  'email'    : sentinel.email1,
                  'firstname': sentinel.firstname1,
                  'lastname' : sentinel.lastname1,
                  'plan_id'  : sentinel.plan_id1,
                  },
                 {'uniqueid' : sentinel.uniqueid2,
                  'email'    : sentinel.email2,
                  'firstname': sentinel.firstname2,
                  'lastname' : sentinel.lastname2,
                  'plan_id'  : sentinel.plan_id2,
                  },
                 {'uniqueid' : sentinel.uniqueid3,
                  'email'    : sentinel.email3,
                  'firstname': sentinel.firstname3,
                  'lastname' : sentinel.lastname3,
                  'plan_id'  : sentinel.plan_id3,
                  },]
        
        returns = [{'success'   : True,
                    'avatar_id' : sentinel.avatar_id1,
                    'account_id': sentinel.account_id1,
                    'server_assigned_password' : sentinel.s_a_p1,
                    },
                   {'success'   : True,
                    'avatar_id' : sentinel.avatar_id2,
                    'account_id': sentinel.account_id2,
                    'server_assigned_password' : sentinel.s_a_p2,
                    },
                   {'success'   : True,
                    'avatar_id' : sentinel.avatar_id3,
                    'account_id': sentinel.account_id3,
                    'server_assigned_password' : sentinel.s_a_p3,
                    },]

        def side_effect(*args):
            return returns.pop(0)
        self.api_iface_create.side_effect = side_effect

        results = group_manager._api_create_users(config, users)

        self.assertEqual(len(results), 3)

        self.assertIs(results[0]['uniqueid'], sentinel.uniqueid1)
        self.assertIs(results[0]['avatar_id'], sentinel.avatar_id1)

        self.assertIs(results[1]['uniqueid'], sentinel.uniqueid2)
        self.assertIs(results[1]['avatar_id'], sentinel.avatar_id2)

        self.assertIs(results[2]['uniqueid'], sentinel.uniqueid3)
        self.assertIs(results[2]['avatar_id'], sentinel.avatar_id3)
        
class TestRunGeneric(unittest.TestCase):
    def setUp(self):
        def config_get_args(str1, str2):
            if str2 == 'api_root':
                return sentinel.api_root
            else:
                return sentinel.promo_code

        self.config = Mock()
        self.config.get = config_get_args
        

        def testfun_nopromo(api_root, user):
            pass

        def testfun_promo(api_root, user, promo_code):
            pass

        self.testfun_nopromo_mock = Mock()
        self.testfun_nopromo = mocksignature(testfun_nopromo, 
                                             self.testfun_nopromo_mock)
        self.testfun_nopromo.return_value = sentinel.testfun_nopromo

        self.testfun_promo_mock = Mock()
        self.testfun_promo = mocksignature(testfun_promo, 
                                           self.testfun_promo_mock)
        self.testfun_promo.return_value = sentinel.testfun_promo
        
    def test_works_nousers_nopromo(self):
        results = group_manager._api_run_generic(self.config,
                                                 self.testfun_nopromo,
                                                 [])
        self.assertEqual(len(results), 0)

    def test_exception_nousers_nopromo(self):
        self.testfun_nopromo.side_effect = api_interface.ApiActionFailedError
        results = group_manager._api_run_generic(self.config,
                                                 self.testfun_nopromo,
                                                 [])
        self.assertEqual(len(results), 0)


    def test_works_nousers_promo(self):
        results = group_manager._api_run_generic(self.config,
                                                 self.testfun_promo,
                                                 [])
        self.assertEqual(len(results), 0)

    def test_works_oneuser_nopromo(self):
        user = {'field1': sentinel.field1, 'field2': sentinel.field2}

        results = group_manager._api_run_generic(self.config,
                                                 self.testfun_nopromo,
                                                 [user])

        self.assertEqual(len(results), 1)
        self.assertIs(results[0], user)
        args, _ = self.testfun_nopromo_mock.call_args
        assert user in args
        assert sentinel.promo_code not in args


    def test_exception_oneuser_nopromo(self):
        user = {'field1': sentinel.field1, 'field2': sentinel.field2}
        self.testfun_nopromo_mock.side_effect = api_interface.ApiActionFailedError
        with self.assertRaises(group_manager.BailApiCall) as cm:
            results = group_manager._api_run_generic(self.config,
                                                     self.testfun_nopromo,
                                                     [user])
        e = cm.exception
        result_list, = e.args
        self.assertEqual(len(result_list), 0)

        
    def test_works_oneuser_promo(self):
        user = {'field1': sentinel.field1, 'field2': sentinel.field2}

        results = group_manager._api_run_generic(self.config,
                                                 self.testfun_promo,
                                                 [user])

        self.assertEqual(len(results), 1)
        self.assertIs(results[0], user)
        args, _ = self.testfun_promo_mock.call_args
        assert user in args
        assert sentinel.promo_code in args

    def test_works_multiuser_nopromo(self):
        users = [{'field1': sentinel.field1_1, 'field2': sentinel.field2_1,},
                 {'field1': sentinel.field1_2, 'field2': sentinel.field2_2,},
                 {'field1': sentinel.field1_3, 'field2': sentinel.field2_3,},]

        results = group_manager._api_run_generic(self.config,
                                                 self.testfun_nopromo,
                                                 users)

        self.assertEqual(len(results), len(users))
        for i, d in enumerate(results):
            self.assertIs(d['field1'], users[i]['field1'])
            self.assertIs(d['field2'], users[i]['field2'])

    def test_exception_multiuser_nopromo(self):
        users = [{'field1': sentinel.field1_1, 'field2': sentinel.field2_1,},
                 {'field1': sentinel.field1_2, 'field2': sentinel.field2_2,},
                 {'field1': sentinel.field1_3, 'field2': sentinel.field2_3,},]

        poplist = copy.copy(users)

        def side_effect(*args, **kwargs):
            if len(poplist) > 1:
                return poplist.pop(0)
            else:
                raise api_interface.ApiActionFailedError()

        self.testfun_nopromo_mock.side_effect = side_effect

        with self.assertRaises(group_manager.BailApiCall) as cm:
            _ = group_manager._api_run_generic(self.config,
                                               self.testfun_nopromo,
                                               users)

        e = cm.exception
        results, = e.args
        self.assertEqual(len(results), len(users) - 1)
        for i, d in enumerate(results):
            self.assertIs(d['field1'], users[i]['field1'])
            self.assertIs(d['field2'], users[i]['field2'])

    def test_works_multiuser_promo(self):
        users = [{'field1': sentinel.field1_1, 'field2': sentinel.field2_1,},
                 {'field1': sentinel.field1_2, 'field2': sentinel.field2_2,},
                 {'field1': sentinel.field1_3, 'field2': sentinel.field2_3,},]

        results = group_manager._api_run_generic(self.config,
                                                 self.testfun_promo,
                                                 users)

        self.assertEqual(len(results), len(users))
        for i, d in enumerate(results):
            self.assertIs(d['field1'], users[i]['field1'])
            self.assertIs(d['field2'], users[i]['field2'])


class TestProcessQuery(unittest.TestCase):
    def setUp(self):
        self.db_conn = Mock()
        self.query = Mock()
        self.cur = Mock()

        self.db_conn.cursor.return_value = self.cur

        self.extras = ['field1', 'field2']


    def test_works_norows_noextras(self):
        self.cur.fetchall.return_value = list()

        results = group_manager._process_query(self.db_conn, self.query)

        self.assertEqual(len(results), 0)

    def test_works_onerow_noextras(self):
        self.cur.fetchall.return_value = [[sentinel.uniqueid]]

        results = group_manager._process_query(self.db_conn, self.query)

        self.assertEqual(len(results), 1)
        self.assertEqual(len(list(results[0].keys())), 1)
        self.assertEqual(results[0]['uniqueid'], sentinel.uniqueid)

    def test_works_multirows_noextras(self):
        id_array = [[sentinel.uniqueid1],
                    [sentinel.uniqueid2],
                    [sentinel.uniqueid3]]
        self.cur.fetchall.return_value = id_array

        results = group_manager._process_query(self.db_conn, self.query)

        self.assertEqual(len(results), 3)
        self.assertEqual(len(list(results[0].keys())), 1)

        for i in range(0,3):
            self.assertIs(results[i]['uniqueid'], id_array[i][0])

    def test_works_norows_extras(self):
        self.cur.fetchall.return_value = list()

        results = group_manager._process_query(self.db_conn, self.query, self.extras)

        self.assertEqual(len(results), 0)
        
    def test_works_onerow_extras(self):
        indiv_array = [[sentinel.uniqueid, sentinel.field1, sentinel.field2]]
        self.cur.fetchall.return_value = indiv_array

        results = group_manager._process_query(self.db_conn, self.query, self.extras)
        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0]), 3)
        
        self.assertIs(results[0]['field1'], sentinel.field1)
        self.assertIs(results[0]['field2'], sentinel.field2)

    def test_works_multirows_extras(self):
        test_array = [[sentinel.uniqueid1, sentinel.field1_1, sentinel.field2_1],
                      [sentinel.uniqueid2, sentinel.field1_2, sentinel.field2_2],
                      [sentinel.uniqueid3, sentinel.field1_3, sentinel.field2_3]]

        self.cur.fetchall.return_value = test_array

        results = group_manager._process_query(self.db_conn, self.query, self.extras)

        self.assertEqual(len(results),3)
        self.assertEqual(len(results[0]), 3)

        for i in range(0,3):
            self.assertIs(results[i]['uniqueid'], test_array[i][0])
            self.assertIs(results[i]['field1'], test_array[i][1])
            self.assertIs(results[i]['field2'], test_array[i][2])

    def test_blows_up_with_bad_extras(self):
        indiv_array = [[sentinel.uniqueid, sentinel.field1, sentinel.field2]]
        self.cur.fetchall.return_value = indiv_array
        
        self.extras.append('field3')

        with self.assertRaises(IndexError):
            results = group_manager._process_query(self.db_conn, 
                                                   self.query, 
                                                   self.extras)


if __name__ == "__main__":
    unittest.main()
